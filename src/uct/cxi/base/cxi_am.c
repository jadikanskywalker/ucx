/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Active Message operations — ep_am_short, ep_am_bcopy.
 *
 * TX model
 * ────────
 * ep_am_short (≤ 184 B payload):
 *   Emit c_cstate_cmd (restricted=0, eq, index_ext from dfa_am_idx_ext) then
 *   c_idc_msg_hdr (dfa_am, match_bits=id, user_ptr=op, data=[hdr|payload]).
 *   The cstate sets the event queue; the IDC msg header carries user_ptr for
 *   the C_EVENT_ACK on the sender.  On C_EVENT_ACK the default progress path
 *   (handler=NULL) returns op to op_pool.
 *
 * ep_am_bcopy (≤ max_bcopy):
 *   Acquires a desc from desc_pool (same pool as RMA put_bcopy), calls
 *   pack_cb to fill the data area, then emits c_full_dma_cmd (restricted=0,
 *   dfa_am, match_bits=id).  On C_EVENT_ACK the put_bcopy_comp handler returns
 *   desc to desc_pool.
 *
 * Both operations target the remote AM OVERFLOW LE via ep->dfa_am.
 * No remote registration or rkey needed — the LE is pre-posted at iface_open.
 *
 * RX model
 * ────────
 * Handled in cxi_iface.c: iface_progress sees C_EVENT_PUT on the AM OVERFLOW
 * LE, extracts am_id from match_bits[4:0], and calls uct_iface_invoke_am.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_am.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_am_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

/*
 * AM bcopy completion: the bounce-buffer desc holds the sent payload.
 * No user callback for bcopy put — just return the descriptor.
 */
static void uct_cxi_am_bcopy_comp(uct_cxi_send_op_t *op)
{
    ucs_mpool_put((uct_cxi_send_desc_t *)op);
}


/* -------------------------------------------------------------------------
 * ep_am_short
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_am_short — post an unrestricted IDC AM message (≤ 184 B payload).
 *
 * Wire format: c_cstate_cmd (restricted=0, sets eq/index_ext) followed by
 * c_idc_msg_hdr (dfa_am, match_bits=id, user_ptr=op).  Data embedded in IDC:
 *   [uint64_t header (8 B)][uint8_t payload (length B)]
 *
 * The receiver's C_EVENT_PUT carries match_bits (am_id), start (IOVA offset),
 * and mlength (8 + length).  iface_progress passes data directly from rx_buf
 * to uct_iface_invoke_am — zero-copy on the receive side.
 *
 * Returns UCS_OK (not UCS_INPROGRESS): source buffer reusable on return.
 * Remote visibility is not guaranteed until the next ep_flush returns UCS_OK.
 */
ucs_status_t uct_cxi_ep_am_short(uct_ep_h tl_ep, uint8_t id,
                                  uint64_t header, const void *payload,
                                  unsigned length)
{
    uct_cxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_am_ep_iface(ep);
    uct_cxi_send_op_t *op;
    int               ret;

    UCT_CHECK_LENGTH(length, 0,
                     C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t), "am_short");

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = NULL;
    op->handler = NULL;   /* default: mpool_put on C_EVENT_ACK */

    /* c_cstate_cmd: unrestricted (restricted=0), sets EQ and idx_ext.
     * user_ptr for C_EVENT_ACK goes in c_idc_msg_hdr.user_ptr, not here. */
    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable = 1;
        cstate.restricted         = 0;
        cstate.index_ext          = ep->dfa_am_idx_ext;
        cstate.eq                 = iface->evtq->eqn;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p am_short c_state emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    /* c_idc_msg_hdr + packed data: [header(8B)][payload(length B)].
     * Fixed-size stack buffer (C_MAX_IDC_PAYLOAD_UNR = 192) avoids VLA.
     * Scope limited to this block (OptimizationStyle: limit local lifetime). */
    {
        uint8_t buf[C_MAX_IDC_PAYLOAD_UNR];
        struct c_idc_msg_hdr idc = {};

        memcpy(buf, &header, sizeof(uint64_t));
        memcpy(buf + sizeof(uint64_t), payload, length);

        idc.dfa        = ep->dfa_am;
        idc.match_bits = (uint64_t)id;
        idc.user_ptr   = (uint64_t)(uintptr_t)op; /* returned in C_EVENT_ACK */

        ucs_info("cxi ep_am_short: id=%u payload_length=%zu match_bits=0x%lx",
                 (unsigned)id, sizeof(uint64_t) + length,
                 (unsigned long)idc.match_bits);
        ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &idc, buf,
                                   sizeof(uint64_t) + length);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p am_short idc_msg emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      AM, SHORT, sizeof(uint64_t) + length);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * ep_am_bcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_am_bcopy — unrestricted DMA AM send via bounce buffer.
 *
 * Acquires a pre-registered uct_cxi_send_desc_t from desc_pool (shared with
 * RMA put_bcopy), calls pack_cb to fill the data area, then posts a
 * c_full_dma_cmd C_CMD_PUT with restricted=0 targeting the remote AM PTE.
 * The NIC delivers data to the remote OVERFLOW LE; the remote iface_progress
 * sees C_EVENT_PUT and dispatches to the AM handler.
 *
 * Returns the number of bytes packed (ssize_t) on success.
 * Source data is in the transport's bounce buffer until C_EVENT_ACK.
 */
ssize_t uct_cxi_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                             uct_pack_callback_t pack_cb, void *arg,
                             unsigned flags)
{
    uct_cxi_ep_t        *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t     *iface = uct_cxi_am_ep_iface(ep);
    uct_cxi_send_desc_t *desc;
    size_t               length;
    int                  ret;

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);

    desc->op.ep      = ep;
    desc->op.comp    = NULL;
    desc->op.handler = uct_cxi_am_bcopy_comp;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_PUT;
        cmd.index_ext          = ep->dfa_am_idx_ext;
        cmd.lac                = desc->lac;
        cmd.event_send_disable = 1;
        cmd.restricted         = 0;   /* unrestricted: targets AM OVERFLOW LE */
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = ep->dfa_am;
        cmd.match_bits         = (uint64_t)id;
        cmd.remote_offset      = 0;   /* NIC places in OVERFLOW at its write ptr */
        cmd.local_addr         = desc->iova;
        cmd.request_len        = (uint32_t)length;
        cmd.user_ptr           = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        ucs_error("cxi ep %p ep_am_bcopy emit failed: %d", ep, ret);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      AM, BCOPY, length);
    return (ssize_t)length;
}
