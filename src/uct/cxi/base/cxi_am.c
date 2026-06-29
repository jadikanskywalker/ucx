/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Active Message operations — ep_am_short, ep_am_bcopy.
 *
 * TX model
 * ────────
 * Both ep_am_short and ep_am_bcopy use c_full_dma_cmd (restricted=0) targeting
 * the remote AM PTE via ep->dfa_am.  No rkey is exchanged — unrestricted DMA
 * routes by DFA (NID+PID+pid_offset) to the pre-posted OVERFLOW LE.
 *
 * ep_am_short (≤ 184 B payload):
 *   Acquires a desc from desc_pool, copies [header(8B)|payload] into desc+1,
 *   then emits c_full_dma_cmd.  The NIC DMA's from the registered desc buffer
 *   into the remote OVERFLOW LE, advancing the remote write pointer per message
 *   (unlike IDC unrestricted, which always writes to le.start).  On C_EVENT_ACK
 *   the bcopy_comp handler returns desc to desc_pool.  Returns UCS_OK (caller's
 *   header+payload are copied into desc and reusable immediately).
 *
 * ep_am_bcopy (≤ max_bcopy):
 *   Same hardware path as ep_am_short but fills desc via pack_cb instead of
 *   memcpy.  Returns ssize_t (bytes packed).
 *
 * RX model
 * ────────
 * iface_progress sees C_EVENT_PUT on the AM OVERFLOW LE, reads buffer_id to
 * identify the receive buffer, and calls uct_iface_invoke_am.  The two-buffer
 * ping-pong (UCT_CXI_AM_MIN_FREE, auto_unlinked) is managed in cxi_iface.c.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_am.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_iov.inl>
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
 * uct_cxi_ep_am_short — unrestricted IDC AM send (≤ 184 B payload).
 *
 * Emits c_cstate_cmd (restricted=0, all events suppressed) followed by
 * c_idc_msg_hdr carrying [header(8B)|payload] as inline data.  Pure
 * fire-and-forget: no desc, no outstanding tracking, no events.  The NIC
 * places the data in the remote OVERFLOW LE at its managed write pointer
 * (manage_local=1 on the OVERFLOW LE).
 *
 * Returns UCS_OK on the same turn; caller's buffers are reusable immediately.
 */
ucs_status_t uct_cxi_ep_am_short(uct_ep_h tl_ep, uint8_t id,
                                  uint64_t header, const void *payload,
                                  unsigned length)
{
    uct_cxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_am_ep_iface(ep);
    uint8_t          buf[C_MAX_IDC_PAYLOAD_UNR]; /* stack: ≤192 B inline */
    int              ret;

    UCT_CHECK_LENGTH(length, 0,
                     C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t), "am_short");

    memcpy(buf, &header, sizeof(uint64_t));
    memcpy(buf + sizeof(uint64_t), payload, length);

    {
        struct c_cstate_cmd cstate    = {};
        cstate.event_send_disable     = 1; /* fire-and-forget: no events */
        cstate.event_success_disable  = 0;
        cstate.restricted             = 0; /* unrestricted → AM OVERFLOW LE */
        cstate.index_ext              = ep->dfa_am_idx_ext;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi ep %p am_short cstate emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa        = ep->dfa_am;
        hdr.match_bits = (uint64_t)id;

        ucs_trace("cxi IDC_SEND: am_id=%u total_len=%zu "
                  "nid=%u pid=%u idx_ext=%u "
                  "wp32=%lu hw_wp32=%lu",
                  (unsigned)id, sizeof(uint64_t) + length,
                  ep->rem_nid, ep->rem_pid, (unsigned)ep->dfa_am_idx_ext,
                  (unsigned long)iface->tx.cmdq->wp32,
                  (unsigned long)iface->tx.cmdq->hw_wp32);

        ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &hdr, buf,
                                  sizeof(uint64_t) + length);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi ep %p am_short idc_msg emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);

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
        cmd.command.opcode       = C_CMD_PUT;
        cmd.index_ext            = ep->dfa_am_idx_ext;
        cmd.lac                  = desc->lac;
        cmd.event_send_disable     = 1; /* fire-and-forget: no events */
        cmd.event_success_disable = 0; /* unrestricted PUT: no ACK; use SEND */
        cmd.restricted           = 0;  /* unrestricted → AM OVERFLOW LE */
        cmd.eq                   = iface->evtq->eqn;
        cmd.dfa                  = ep->dfa_am;
        cmd.match_bits           = (uint64_t)id;
        cmd.remote_offset        = 0;  /* NIC places at its managed write pointer */
        cmd.local_addr           = desc->iova;
        cmd.request_len          = (uint32_t)length;
        cmd.user_ptr             = (uint64_t)(uintptr_t)desc;

        ucs_trace("cxi DMA_PUT_SEND: am_id=%u len=%u "
                  "nid=%u pid=%u idx_ext=%u eq=%u lac=%u "
                  "local_addr=0x%lx wp32=%lu hw_wp32=%lu",
                  (unsigned)id, cmd.request_len,
                  ep->rem_nid, ep->rem_pid, (unsigned)ep->dfa_am_idx_ext,
                  (unsigned)cmd.eq, (unsigned)cmd.lac,
                  (unsigned long)cmd.local_addr,
                  (unsigned long)iface->tx.cmdq->wp32,
                  (unsigned long)iface->tx.cmdq->hw_wp32);

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


/* -------------------------------------------------------------------------
 * ep_am_zcopy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_am_zcopy — unrestricted DMA AM send directly from user buffer.
 *
 * Zero-copy: the NIC DMAs from the caller's registered IOV buffer into the
 * remote AM PRIORITY ME.  The caller must keep the buffer valid until the
 * completion fires (C_EVENT_ACK → uct_invoke_completion).
 *
 * Header handling (max_hdr = 8, CXI has no send-side scatter-gather):
 *   Contiguous (header + header_length == iov[0].buffer):
 *     Single DMA from header pointer for header_length + iov_length.
 *   Non-contiguous (header from stack / different allocation):
 *     Header packed into cmd.header_data (8 bytes out-of-band).
 *     UCT_CXI_AM_HDR_FLAG set in match_bits.  Receiver prepends
 *     header_data before payload in the ME buffer.
 *
 * max_zcopy = buf_size - 8: payload must fit in one receiver ME buffer
 * (8 bytes reserved for header_data prepend).
 */
ucs_status_t uct_cxi_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id,
                                  const void *header, unsigned header_length,
                                  const uct_iov_t *iov, size_t iovcnt,
                                  unsigned flags, uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface = uct_cxi_am_ep_iface(ep);
    uct_cxi_mem_handle_t *memh  = (uct_cxi_mem_handle_t *)iov[0].memh;
    size_t                iov_length = uct_iov_get_length(iov);
    uct_cxi_send_op_t    *op;
    int                   ret;

    UCT_CHECK_LENGTH(header_length, 0, sizeof(uint64_t), "am_zcopy header");
    UCT_CHECK_LENGTH(header_length + iov_length, 0,
                     iface->am.buf_size - sizeof(uint64_t),
                     "am_zcopy total");

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = comp;
    op->handler = NULL;

    {
        struct c_full_dma_cmd cmd = {};
        int contiguous = (header_length > 0) &&
                         ((const uint8_t *)header + header_length ==
                          (const uint8_t *)iov[0].buffer);

        cmd.command.opcode        = C_CMD_PUT;
        cmd.index_ext             = ep->dfa_am_idx_ext;
        cmd.lac                   = memh->cxi_md->lac;
        cmd.event_send_disable    = 1;
        cmd.event_success_disable = 0;
        cmd.restricted            = 0;
        cmd.eq                    = iface->evtq->eqn;
        cmd.dfa                   = ep->dfa_am;
        cmd.remote_offset         = 0;
        cmd.user_ptr              = (uint64_t)(uintptr_t)op;

        if (contiguous) {
            cmd.match_bits  = (uint64_t)id;
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)header;
            cmd.request_len = (uint32_t)(header_length + iov_length);
        } else if (header_length > 0) {
            cmd.match_bits  = (uint64_t)id | UCT_CXI_AM_HDR_FLAG;
            cmd.header_data = 0;
            memcpy(&cmd.header_data, header, header_length);
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)iov[0].buffer;
            cmd.request_len = (uint32_t)iov_length;
        } else {
            cmd.match_bits  = (uint64_t)id;
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)iov[0].buffer;
            cmd.request_len = (uint32_t)iov_length;
        }

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p ep_am_zcopy emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      AM, ZCOPY, header_length + iov_length);
    return UCS_INPROGRESS;
}
