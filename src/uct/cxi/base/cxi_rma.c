/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI RMA operations: put/get short, bcopy and zcopy.
 *
 * All use restricted mode: the NIC routes a command to the target's RMA PTE
 * of the target buffer's LAC (ep->dfa_rma[rkey->lac]). A restricted packet
 * carries no LAC, so the PTE is the only signal of which LAC's address
 * context resolves remote_offset. UCT_CXI_MAX_LACS is 1 for now.
 *
 * Completions: ACK for puts, REPLY for gets. An IDC put_short has no
 * user_ptr in its header, so a c_cstate_cmd carrying it precedes the IDC put.
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
 * Synchronous GET: read into the scratch buffer iface->tx.get_short_buf, spin
 * on progress until the REPLY, then copy to the caller. At most one is in
 * flight (single-threaded worker).
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

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

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
        cmd.eq                 = iface->tx_eq.evtq->eqn;
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
        uct_cxi_tx_emit_error(ep, "ep_get_short", ret);
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
 * Inline PUT of up to C_MAX_IDC_PAYLOAD_RES bytes, copied into the command.
 * The completion is tracked by the ep alone (uct_cxi_ep_short_user_ptr);
 * remote visibility is only guaranteed once ep_flush returns UCS_OK.
 */
ucs_status_t uct_cxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                   unsigned length, uint64_t remote_addr,
                                   uct_rkey_t rkey)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_rma_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    int                   ret;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_RES, "put_short");

    ucs_trace("cxi put_short ep %p len %u rkey %p iova 0x%lx "
              "remote_addr 0x%lx final_offset 0x%lx lac %u",
              ep, length, rkey_p,
              (unsigned long)rkey_p->iova,
              (unsigned long)remote_addr,
              (unsigned long)(rkey_p->iova + remote_addr),
              (unsigned)rkey_p->lac);

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 1;
        cstate.index_ext           = ep->dfa_rma_idx_ext[rkey_p->lac];
        cstate.eq                  = iface->tx_eq.evtq->eqn;
        cstate.user_ptr            = uct_cxi_ep_short_user_ptr(ep);

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
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

/* put_bcopy completion: just return the desc. */
static void uct_cxi_put_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    ucs_mpool_put((uct_cxi_send_desc_t *)op);
}

/* get_bcopy completion: unpack the data (only on success), complete, free. */
static void uct_cxi_get_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_send_desc_t *desc = (uct_cxi_send_desc_t *)op;

    if (status == UCS_OK) {
        desc->unpack_cb(desc->unpack_arg, desc + 1, desc->length);
    }
    if (op->comp != NULL) {
        uct_invoke_completion(op->comp, status);
    }
    ucs_mpool_put(desc);
}


/* -------------------------------------------------------------------------
 * ep_put_bcopy
 * -------------------------------------------------------------------------
 */

/*
 * PUT via a bounce buffer from desc_pool, filled by pack_cb. Returns the
 * packed length, or a negative status.
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

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

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
        cmd.eq                 = iface->tx_eq.evtq->eqn;
        cmd.dfa                = ep->dfa_rma[rkey_p->lac];
        cmd.remote_offset      = rkey_p->iova + remote_addr;
        cmd.local_addr         = desc->iova;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        uct_cxi_tx_emit_error(ep, "ep_put_bcopy", ret);
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

/* GET into a bounce buffer; uct_cxi_get_bcopy_comp unpacks it on the REPLY. */
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

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

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
        cmd.event_send_disable = 1;
        cmd.eq                 = iface->tx_eq.evtq->eqn;
        cmd.local_addr         = desc->iova;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)desc;

        if (ucs_unlikely(rkey_p->is_rndv)) {
            /* Unexpected-rendezvous pull: unlike RMA this targets the sender's
             * rendezvous source PTE (rdzv_get_idx), matching on its rdzv op
             * id, with remote_addr its real offset. Built in place: dfa and
             * index_ext are bit-fields. */
            uct_cxi_md_t     *rdzv_md = uct_cxi_iface_md(iface);
            union c_fab_addr  rdzv_dfa;
            uint8_t           rdzv_idx_ext;

            cxi_build_dfa(ep->rem_nid, ep->rem_pid, rdzv_md->pid_bits,
                         rdzv_md->cxi_dev->info.rdzv_get_idx, &rdzv_dfa,
                         &rdzv_idx_ext);
            cmd.lac           = desc->lac;
            cmd.restricted    = 0;
            cmd.initiator     = iface->match_id;
            cmd.dfa           = rdzv_dfa;
            cmd.index_ext     = rdzv_idx_ext;
            cmd.remote_offset = remote_addr;
            cmd.match_bits    = rkey_p->rendezvous_id;
        } else {
            cmd.index_ext     = ep->dfa_rma_idx_ext[rkey_p->lac];
            cmd.lac           = desc->lac;
            cmd.restricted    = 1;
            cmd.dfa           = ep->dfa_rma[rkey_p->lac];
            cmd.remote_offset = rkey_p->iova + remote_addr;
        }

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        uct_cxi_tx_emit_error(ep, "ep_get_bcopy", ret);
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

/* DMA PUT from a registered buffer (iovcnt == 1); completes on the ACK. */
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

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

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
        cmd.eq                 = iface->tx_eq.evtq->eqn;
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

/* DMA GET into a registered buffer (iovcnt == 1); completes on the REPLY. */
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

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

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
        cmd.event_send_disable = 1;
        cmd.eq                 = iface->tx_eq.evtq->eqn;
        cmd.local_addr         = local_mh->iova_offset +
                                 (uint64_t)(uintptr_t)iov[0].buffer;
        cmd.request_len        = (uint32_t)uct_iov_get_length(iov);
        cmd.user_ptr           = (uint64_t)(uintptr_t)op;

        if (ucs_unlikely(rkey_p->is_rndv)) {
            /* Unexpected-rendezvous pull, as in uct_cxi_ep_get_bcopy(). */
            uct_cxi_md_t     *rdzv_md = uct_cxi_iface_md(iface);
            union c_fab_addr  rdzv_dfa;
            uint8_t           rdzv_idx_ext;

            cxi_build_dfa(ep->rem_nid, ep->rem_pid, rdzv_md->pid_bits,
                         rdzv_md->cxi_dev->info.rdzv_get_idx, &rdzv_dfa,
                         &rdzv_idx_ext);
            cmd.lac           = local_mh->cxi_md->lac;
            cmd.restricted    = 0;
            cmd.initiator     = iface->match_id;
            cmd.dfa           = rdzv_dfa;
            cmd.index_ext     = rdzv_idx_ext;
            cmd.remote_offset = remote_addr;
            cmd.match_bits    = rkey_p->rendezvous_id;
            ucs_debug("cxi RNDV-GET-ZCOPY ep=%p rem_nid=%u rem_pid=%u "
                     "pid_bits=%u rdzv_get_idx=%u lac=%u index_ext=%u "
                     "remote_offset=0x%lx match_bits=0x%lx local_addr=0x%lx "
                     "request_len=%u", ep, ep->rem_nid, ep->rem_pid,
                     (unsigned)rdzv_md->pid_bits,
                     (unsigned)rdzv_md->cxi_dev->info.rdzv_get_idx,
                     (unsigned)cmd.lac, (unsigned)cmd.index_ext,
                     (unsigned long)cmd.remote_offset,
                     (unsigned long)cmd.match_bits,
                     (unsigned long)cmd.local_addr, cmd.request_len);
        } else {
            cmd.index_ext     = ep->dfa_rma_idx_ext[rkey_p->lac];
            cmd.lac           = local_mh->cxi_md->lac;
            cmd.restricted    = 1;
            cmd.dfa           = ep->dfa_rma[rkey_p->lac];
            cmd.remote_offset = rkey_p->iova + remote_addr;
        }

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
