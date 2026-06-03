/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI RMA operations — ep_put_short, ep_put_zcopy, ep_get_zcopy.
 *
 * Restricted-mode DMA model
 * ─────────────────────────
 * Both PUT and GET use c_full_dma_cmd with restricted=1.  The NIC routes the
 * command to the remote peer's RMA portal at pid_offset = rkey->lac via the
 * precomputed DFA.  The remote portal's catch-all LE (posted at iface_open
 * for LAC 0, lazily for LACs 1-7) tells the NIC which IOMMU context (AC) to
 * use for the remote memory access.
 *
 * PUT short: data is inline in the IDC command — no local mem_reg needed, no DMA.
 *   c_idc_hdr carries no user_ptr, so a c_cstate_cmd is emitted first.
 *   The cstate carries user_ptr, eq, index_ext, and restricted; the NIC pairs
 *   it with the following IDC put and fires C_EVENT_ACK with that user_ptr.
 *   Both cstate and IDC are emitted before cxi_cq_ring (single doorbell).
 *
 * PUT zcopy: NIC DMA from app's registered IOVA.  Completion: C_EVENT_ACK.
 * GET zcopy: NIC reads remote memory → local registered buffer.  Completion: C_EVENT_REPLY.
 *
 * DFA lazy construction
 * ─────────────────────
 * ep->dfa_rma[lac] is built on first use of that LAC (bit lac of
 * ep->dfa_rma_valid).  For the default build (UCT_CXI_MAX_LACS = 1) LAC 0
 * is always pre-built at ep_create so the lazy branch is dead code.
 *
 * Per-LAC PTE lazy open
 * ─────────────────────
 * iface->rma.pte[0] is opened at iface_init.  For UCT_CXI_MAX_LACS = 8,
 * PTEs 1-7 are opened by uct_cxi_rma_ensure_lac() on first use.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_rma.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_iov.inl>
#include <ucs/debug/log.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>
#include <errno.h>


/* -------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------
 */

static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_rma_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}


/* -------------------------------------------------------------------------
 * ep_get_short
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_get_short — synchronous inline GET from remote memory.
 *
 * Posts a restricted-mode DMA GET into iface->tx.get_short_buf (a small
 * separately-allocated, pre-registered scratch buffer), spins on
 * iface_progress until C_EVENT_REPLY arrives, then copies the data into
 * the caller's buffer.  Returns UCS_OK with data ready on return.
 *
 * The scratch buffer is separate from the iface struct to keep the NIC's
 * DMA writes out of the CPU-hot struct pages.
 *
 * Thread safety: single-threaded poll model; at most one get_short in
 * flight at a time is guaranteed by the UCT single-worker contract.
 */
ucs_status_t uct_cxi_ep_get_short(uct_ep_h tl_ep, void *buffer,
                                   unsigned length, uint64_t remote_addr,
                                   uct_rkey_t rkey)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_op_t    *op;
    unsigned              pre;
    int                   ret;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_RES, "get_short");

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = NULL;
    op->handler = NULL;

    pre = ep->outstanding;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_GET;
        cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
        cmd.lac                = iface->tx.get_short_mh.cxi_md->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 1;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = iface->tx.get_short_mh.iova_offset +
                                 (uint64_t)(uintptr_t)iface->tx.get_short_buf;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p ep_get_short emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    /* Spin until C_EVENT_REPLY is processed and outstanding returns to pre. */
    while (ep->outstanding > pre) {
        uct_iface_progress((uct_iface_h)&iface->super.super);
    }

    memcpy(buffer, iface->tx.get_short_buf, length);

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      GET, SHORT, length);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * ep_put_short
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_put_short — post an inline restricted-mode PUT.
 *
 * Data (≤ C_MAX_IDC_PAYLOAD_RES = 224 B, cassini_user_defs.h hardware
 * constant) is embedded directly in the IDC command; the source buffer may
 * be reused as soon as this function returns.
 *
 * Completion tracking: c_idc_hdr carries no user_ptr.  The correct CXI
 * pattern (mirroring libfabric's cxip_rma_emit_idc) is to emit a
 * c_cstate_cmd first: it carries user_ptr, eq, index_ext, and restricted,
 * and the NIC pairs it with the following IDC put to fire C_EVENT_ACK with
 * that user_ptr.  Both cstate and IDC are emitted before the single
 * cxi_cq_ring, so the NIC sees them as one operation.
 *
 * Returns UCS_OK (not UCS_INPROGRESS): source buffer is reusable on return,
 * but remote visibility is not guaranteed until ep_flush returns UCS_OK.
 */
ucs_status_t uct_cxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                   unsigned length, uint64_t remote_addr,
                                   uct_rkey_t rkey)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_op_t    *op;
    int                   ret;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_RES, "put_short");

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = NULL;
    op->handler = NULL;

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 1;
        cstate.index_ext           = ep->dfa_rma_idx_ext[rkey_p->lac];
        cstate.eq                  = iface->evtq->eqn;
        cstate.user_ptr            = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p cxi_cq_emit_c_state failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_put_cmd idc = {};
        idc.idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
        idc.idc_header.remote_offset = rkey_p->iova + remote_addr;

        ret = cxi_cq_emit_idc_put(iface->tx.cmdq, &idc, buffer, (size_t)length);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p cxi_cq_emit_idc_put failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      PUT, SHORT, length);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * ep_put_bcopy / ep_get_bcopy — completion handlers
 * -------------------------------------------------------------------------
 */

/*
 * put_bcopy completion: no user callback — the source data is already in the
 * bounce buffer which belongs to the transport.  Just return the desc.
 */
static void uct_cxi_put_bcopy_comp(uct_cxi_send_op_t *op)
{
    ucs_mpool_put((uct_cxi_send_desc_t *)op);
}

/*
 * get_bcopy completion: NIC has delivered remote data into desc's buffer.
 * Call the unpack callback to deliver to the caller, invoke any user
 * completion, then return the descriptor.
 */
static void uct_cxi_get_bcopy_comp(uct_cxi_send_op_t *op)
{
    uct_cxi_send_desc_t *desc = (uct_cxi_send_desc_t *)op;

    desc->unpack_cb(desc->unpack_arg, desc + 1, desc->length);
    if (op->comp != NULL) {
        uct_invoke_completion(op->comp, UCS_OK);
    }
    ucs_mpool_put(desc);
}


/* -------------------------------------------------------------------------
 * ep_put_bcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_put_bcopy — restricted-mode DMA PUT via bounce buffer.
 *
 * Acquires a pre-registered uct_cxi_send_desc_t from desc_pool, calls
 * pack_cb to fill the data area, then posts a c_full_dma_cmd C_CMD_PUT.
 * The descriptor's pre-computed iova/lac eliminate per-op IOVA arithmetic.
 *
 * Returns the number of bytes packed (ssize_t) on success, or a negative
 * ucs_status_t cast on resource exhaustion.  Source data is owned by the
 * transport from return until C_EVENT_ACK; caller may reuse its buffer
 * immediately.
 */
ssize_t uct_cxi_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                              void *arg, uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_desc_t  *desc;
    size_t                length;
    int                   ret;

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);

    desc->op.ep      = ep;
    desc->op.comp    = NULL;
    desc->op.handler = uct_cxi_put_bcopy_comp;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_PUT;
        cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
        cmd.lac                = desc->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 1;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = desc->iova;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        ucs_error("cxi ep %p ep_put_bcopy emit failed: %d", ep, ret);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      PUT, BCOPY, length);
    return (ssize_t)length;
}


/* -------------------------------------------------------------------------
 * ep_get_bcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_get_bcopy — restricted-mode DMA GET via bounce buffer.
 *
 * Posts a c_full_dma_cmd C_CMD_GET targeting desc's pre-registered data
 * area.  On C_EVENT_REPLY, uct_cxi_get_bcopy_comp calls unpack_cb to
 * deliver the data to the caller, then invokes comp.
 *
 * Returns UCS_INPROGRESS; caller polls iface_progress until comp fires.
 */
ucs_status_t uct_cxi_ep_get_bcopy(uct_ep_h tl_ep,
                                   uct_unpack_callback_t unpack_cb,
                                   void *arg, size_t length,
                                   uint64_t remote_addr, uct_rkey_t rkey,
                                   uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_desc_t  *desc;
    int                   ret;

    UCT_CHECK_LENGTH(length, 0, iface->tx.max_bcopy, "get_bcopy");

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }

    desc->op.ep        = ep;
    desc->op.comp      = comp;
    desc->op.handler   = uct_cxi_get_bcopy_comp;
    desc->unpack_cb    = unpack_cb;
    desc->unpack_arg   = arg;
    desc->length       = length;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_GET;
        cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
        cmd.lac                = desc->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 1;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = desc->iova;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        ucs_error("cxi ep %p ep_get_bcopy emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      GET, BCOPY, length);
    return UCS_INPROGRESS;
}


/* -------------------------------------------------------------------------
 * ep_put_zcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_put_zcopy — post a restricted-mode DMA PUT command.
 *
 * Supports iovcnt == 1.  Completion arrives as C_EVENT_ACK on the shared EQ.
 * Returns UCS_INPROGRESS; the caller polls iface_progress until the ACK fires.
 */
ucs_status_t uct_cxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                   size_t iovcnt, uint64_t remote_addr,
                                   uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep      = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface   = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p  = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_mem_handle_t *local_mh = (uct_cxi_mem_handle_t *)iov[0].memh;
    uct_cxi_send_op_t    *op;
    int                   ret;

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = comp;
    op->handler = NULL;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_PUT;
        cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
        cmd.lac                = local_mh->cxi_md->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 1;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = local_mh->iova_offset +
                                 (uint64_t)(uintptr_t)iov[0].buffer;
        cmd.request_len        = (uint32_t)uct_iov_get_length(iov);
        cmd.user_ptr           = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p cxi_cq_emit_dma PUT failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      PUT, ZCOPY, uct_iov_get_length(iov));
    return UCS_INPROGRESS;
}


/* -------------------------------------------------------------------------
 * ep_get_zcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_get_zcopy — post a restricted-mode DMA GET command.
 *
 * Supports iovcnt == 1.  The NIC reads from remote_addr (via the remote RMA
 * portal identified by rkey->lac) and writes into the local buffer.
 * Completion arrives as C_EVENT_REPLY on the shared EQ.
 * Returns UCS_INPROGRESS; the caller polls iface_progress until the reply fires.
 */
ucs_status_t uct_cxi_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                   size_t iovcnt, uint64_t remote_addr,
                                   uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep      = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface   = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p  = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_mem_handle_t *local_mh = (uct_cxi_mem_handle_t *)iov[0].memh;
    uct_cxi_send_op_t    *op;
    int                   ret;

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = comp;
    op->handler = NULL;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_GET;
        cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
        cmd.lac                = local_mh->cxi_md->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 1;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = local_mh->iova_offset +
                                 (uint64_t)(uintptr_t)iov[0].buffer;
        cmd.request_len        = (uint32_t)uct_iov_get_length(iov);
        cmd.user_ptr           = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p cxi_cq_emit_dma GET failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      GET, ZCOPY, uct_iov_get_length(iov));
    return UCS_INPROGRESS;
}
