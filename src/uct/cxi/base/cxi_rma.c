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
#include "config.h"
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


/*
 * Target of an unexpected-rendezvous pull: unlike RMA, the sender's rendezvous
 * source PTE (rdzv_get_idx), matching on its rdzv op id, with \a remote_addr
 * its real offset.
 */
static void
uct_cxi_rma_rndv_get_target(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                            const uct_cxi_rkey_t *rkey_p, uint64_t remote_addr,
                            struct c_full_dma_cmd *cmd)
{
    uct_cxi_md_t *md = uct_cxi_iface_md(iface);
    union c_fab_addr dfa;
    uint8_t idx_ext;

    /* index_ext is a bit-field, so it is built in a local */
    cxi_build_dfa(ep->rem_nid, ep->rem_pid, md->pid_bits,
                  md->cxi_dev->info.rdzv_get_idx, &dfa, &idx_ext);
    cmd->initiator     = iface->match_id;
    cmd->dfa           = dfa;
    cmd->index_ext     = idx_ext;
    cmd->remote_offset = remote_addr;
    cmd->match_bits    = rkey_p->rendezvous_id;
    ucs_debug("cxi rndv get ep %p nid %u pid %u rdzv_get_idx %u "
              "remote_offset 0x%lx match_bits 0x%lx len %u",
              ep, ep->rem_nid, ep->rem_pid, md->cxi_dev->info.rdzv_get_idx,
              (unsigned long)cmd->remote_offset, (unsigned long)cmd->match_bits,
              cmd->request_len);
}

/* Set the target of a GET: the RMA PTE of the rkey's LAC, or a rendezvous. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_rma_get_target(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                       const uct_cxi_rkey_t *rkey_p, uint64_t remote_addr,
                       struct c_full_dma_cmd *cmd)
{
    if (ucs_unlikely(rkey_p->is_rndv)) {
        uct_cxi_rma_rndv_get_target(ep, iface, rkey_p, remote_addr, cmd);
        return;
    }

    cmd->index_ext     = ep->dfa_rma_idx_ext[rkey_p->lac];
    cmd->restricted    = 1;
    cmd->dfa           = ep->dfa_rma[rkey_p->lac];
    cmd->remote_offset = rkey_p->iova + remote_addr;
}

/*
 * Synchronous GET: read into the scratch buffer iface->tx.get_short_buf, spin
 * on progress until the REPLY, then copy to the caller. At most one is in
 * flight (single-threaded worker).
 */
ucs_status_t uct_cxi_ep_get_short(uct_ep_h tl_ep, void *buffer, unsigned length,
                                  uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_full_dma_cmd cmd    = {};
    uct_cxi_send_op_t *op;
    unsigned pre;
    ucs_status_t status;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_RES, "get_short");

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    uct_cxi_send_op_set(op, ep, NULL, NULL);

    cmd.command.opcode     = C_CMD_GET;
    cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
    cmd.lac                = iface->tx.get_short_mh.cxi_md->lac;
    cmd.event_send_disable = 1;
    cmd.restricted         = 1;
    cmd.eq                 = iface->tx_eq.evtq->eqn;
    cmd.dfa                = ep->dfa_rma[rkey_p->lac];
    cmd.remote_offset      = rkey_p->iova + remote_addr;
    cmd.local_addr         = uct_cxi_mem_iova(&iface->tx.get_short_mh,
                                              iface->tx.get_short_buf);
    cmd.request_len        = (uint32_t)length;
    cmd.user_ptr           = (uint64_t)(uintptr_t)op;

    pre    = ep->outstanding;
    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_get_short");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(op);
        return status;
    }

    /* Spin until C_EVENT_REPLY is processed and outstanding returns to pre */
    while (ep->outstanding > pre) {
        uct_iface_progress((uct_iface_h)&iface->super.super);
    }

    memcpy(buffer, iface->tx.get_short_buf, length);

    UCT_TL_EP_STAT_OP(&ep->super, GET, SHORT, length);
    return UCS_OK;
}

/*
 * Inline PUT of up to C_MAX_IDC_PAYLOAD_RES bytes, copied into the command.
 * The completion is tracked by the ep alone (uct_cxi_ep_short_user_ptr);
 * remote visibility is only guaranteed once ep_flush returns UCS_OK.
 */
ucs_status_t uct_cxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                  unsigned length, uint64_t remote_addr,
                                  uct_rkey_t rkey)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_cstate_cmd cstate   = {};
    struct c_idc_put_cmd idc     = {};
    int ret;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_RES, "put_short");

    ucs_trace("cxi put_short ep %p len %u rkey %p iova 0x%lx "
              "remote_addr 0x%lx final_offset 0x%lx lac %u",
              ep, length, rkey_p, (unsigned long)rkey_p->iova,
              (unsigned long)remote_addr,
              (unsigned long)(rkey_p->iova + remote_addr),
              (unsigned)rkey_p->lac);

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    cstate.event_send_disable = 1;
    cstate.restricted         = 1;
    cstate.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
    cstate.eq                 = iface->tx_eq.evtq->eqn;
    cstate.user_ptr           = uct_cxi_ep_short_user_ptr(ep);

    ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, "ep_put_short", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    idc.idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
    idc.idc_header.remote_offset = rkey_p->iova + remote_addr;

    ret = cxi_cq_emit_idc_put(iface->tx.cmdq, &idc, buffer, length);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, "ep_put_short", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    uct_cxi_ep_tx_commit(ep, iface);

    UCT_TL_EP_STAT_OP(&ep->super, PUT, SHORT, length);
    return UCS_OK;
}

/* Unpack the data (only on success), complete and free the desc */
static void uct_cxi_get_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_send_desc_t *desc = (uct_cxi_send_desc_t*)op;

    if (status == UCS_OK) {
        desc->unpack_cb(desc->unpack_arg, desc + 1, desc->length);
    }

    if (op->comp != NULL) {
        uct_invoke_completion(op->comp, status);
    }

    ucs_mpool_put(desc);
}

/*
 * PUT via a bounce buffer from desc_pool, filled by pack_cb. Returns the
 * packed length, or a negative status.
 */
ssize_t uct_cxi_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                             void *arg, uint64_t remote_addr, uct_rkey_t rkey)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_full_dma_cmd cmd    = {};
    uct_cxi_send_desc_t *desc;
    size_t length;
    ucs_status_t status;

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);

    uct_cxi_send_op_set(&desc->op, ep, NULL, uct_cxi_send_desc_put_comp);

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

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_put_bcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(desc);
        return status;
    }

    UCT_TL_EP_STAT_OP(&ep->super, PUT, BCOPY, length);
    return length;
}

/* GET into a bounce buffer; uct_cxi_get_bcopy_comp unpacks it on the REPLY. */
ucs_status_t uct_cxi_ep_get_bcopy(uct_ep_h tl_ep,
                                  uct_unpack_callback_t unpack_cb, void *arg,
                                  size_t length, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_full_dma_cmd cmd    = {};
    uct_cxi_send_desc_t *desc;
    ucs_status_t status;

    UCT_CHECK_LENGTH(length, 0, iface->tx.max_bcopy, "get_bcopy");

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }

    uct_cxi_send_op_set(&desc->op, ep, comp, uct_cxi_get_bcopy_comp);
    desc->unpack_cb  = unpack_cb;
    desc->unpack_arg = arg;
    desc->length     = length;

    cmd.command.opcode     = C_CMD_GET;
    cmd.event_send_disable = 1;
    cmd.eq                 = iface->tx_eq.evtq->eqn;
    cmd.lac                = desc->lac;
    cmd.local_addr         = desc->iova;
    cmd.request_len        = (uint32_t)length;
    cmd.user_ptr           = (uint64_t)(uintptr_t)desc;
    uct_cxi_rma_get_target(ep, iface, rkey_p, remote_addr, &cmd);

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_get_bcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(desc);
        return status;
    }

    UCT_TL_EP_STAT_OP(&ep->super, GET, BCOPY, length);
    return UCS_INPROGRESS;
}

/* DMA PUT from a registered buffer (iovcnt == 1); completes on the ACK. */
ucs_status_t uct_cxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_cxi_ep_t *ep               = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface         = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p   = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    uct_cxi_mem_handle_t *local_mh = (uct_cxi_mem_handle_t*)iov[0].memh;
    struct c_full_dma_cmd cmd      = {};
    uct_cxi_send_op_t *op;
    ucs_status_t status;

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    uct_cxi_send_op_set(op, ep, comp, NULL);

    cmd.command.opcode     = C_CMD_PUT;
    cmd.index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
    cmd.lac                = local_mh->cxi_md->lac;
    cmd.event_send_disable = 1;
    cmd.restricted         = 1;
    cmd.eq                 = iface->tx_eq.evtq->eqn;
    cmd.dfa                = ep->dfa_rma[rkey_p->lac];
    cmd.remote_offset      = rkey_p->iova + remote_addr;
    cmd.local_addr         = uct_cxi_mem_iova(local_mh, iov[0].buffer);
    cmd.request_len        = (uint32_t)uct_iov_get_length(iov);
    cmd.user_ptr           = (uint64_t)(uintptr_t)op;

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_put_zcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(op);
        return status;
    }

    UCT_TL_EP_STAT_OP(&ep->super, PUT, ZCOPY, uct_iov_get_length(iov));
    return UCS_INPROGRESS;
}

/* DMA GET into a registered buffer (iovcnt == 1); completes on the REPLY. */
ucs_status_t uct_cxi_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
    uct_cxi_ep_t *ep               = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface         = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p   = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    uct_cxi_mem_handle_t *local_mh = (uct_cxi_mem_handle_t*)iov[0].memh;
    struct c_full_dma_cmd cmd      = {};
    uct_cxi_send_op_t *op;
    ucs_status_t status;

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    uct_cxi_send_op_set(op, ep, comp, NULL);

    cmd.command.opcode     = C_CMD_GET;
    cmd.event_send_disable = 1;
    cmd.eq                 = iface->tx_eq.evtq->eqn;
    cmd.lac                = local_mh->cxi_md->lac;
    cmd.local_addr         = uct_cxi_mem_iova(local_mh, iov[0].buffer);
    cmd.request_len        = (uint32_t)uct_iov_get_length(iov);
    cmd.user_ptr           = (uint64_t)(uintptr_t)op;
    uct_cxi_rma_get_target(ep, iface, rkey_p, remote_addr, &cmd);

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_get_zcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(op);
        return status;
    }

    UCT_TL_EP_STAT_OP(&ep->super, GET, ZCOPY, uct_iov_get_length(iov));
    return UCS_INPROGRESS;
}
