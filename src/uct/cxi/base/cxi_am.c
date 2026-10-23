/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Active Message operations -- ep_am_short, ep_am_bcopy, ep_am_zcopy.
 *
 * TX model
 * ────────
 * All three send an unrestricted message to the remote AM PTE, addressed by
 * ep->dfa_am (NID+PID+pid_offset); no rkey is exchanged. Each is counted
 * against its ep and the interface's TX queue until its completion event, and
 * is charged against the credits the target granted (see cxi_fc.h).
 *
 * ep_am_short (header + payload <= C_MAX_IDC_PAYLOAD_UNR):
 *   An unrestricted IDC message: the NIC takes the bytes from the command
 *   queue, so there is no descriptor and the caller's buffers are reusable at
 *   once. Its completion (an ACK on the TX EQ) carries the ep and the
 *   message's flow-control charge in its user_ptr, see cxi_ep.h.
 *
 * ep_am_bcopy (<= max_bcopy):
 *   Takes a pre-registered uct_cxi_send_desc_t from desc_pool, fills it with
 *   pack_cb, and posts a C_CMD_PUT from it. The descriptor goes back to the
 *   pool on the ACK. Returns the number of bytes packed.
 *
 * ep_am_zcopy (<= max_zcopy):
 *   Posts a C_CMD_PUT straight from the caller's registered buffer; the
 *   caller's completion fires on the ACK.
 *
 * RX model
 * ────────
 * iface_progress sees C_EVENT_PUT on the AM list, reads buffer_id to find
 * which buffer of the receive ring the NIC wrote into, and calls
 * uct_iface_invoke_am. The ring (several buffers, each a manage_local list
 * entry that unlinks itself near its end and is reposted) is managed in
 * cxi_iface.c.
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
static void uct_cxi_am_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
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
 * Sends [header(8B)|payload] as one inline IDC message (see
 * uct_cxi_ep_idc_send). The NIC places the data in the remote AM list at its
 * managed write pointer. The send is tracked by its completion, which is what
 * lets a send that never arrived be noticed and its credits taken back.
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
    unsigned         units = UCT_CXI_FC_UNITS(sizeof(uint64_t) + length);
    uint64_t         fcbits;
    ucs_status_t     status;
    int              credited;

    UCT_CHECK_LENGTH(length, 0,
                     C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t), "am_short");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->am.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM,
                                UCT_CXI_FC_SLOTS_AM, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }
    fcbits = uct_cxi_fc_pb_bits(ep, iface);

    memcpy(buf, &header, sizeof(uint64_t));
    memcpy(buf + sizeof(uint64_t), payload, length);

    ucs_trace("cxi IDC_SEND: am_id=%u total_len=%zu "
              "nid=%u pid=%u idx_ext=%u "
              "wp32=%lu hw_wp32=%lu",
              (unsigned)id, sizeof(uint64_t) + length,
              ep->rem_nid, ep->rem_pid, (unsigned)ep->dfa_am_idx_ext,
              (unsigned long)iface->tx.cmdq->wp32,
              (unsigned long)iface->tx.cmdq->hw_wp32);

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_am, ep->dfa_am_idx_ext,
                                 (uint64_t)id | fcbits, 0, buf,
                                 sizeof(uint64_t) + length, UCT_CXI_FC_AM,
                                 units, credited, "am_short");
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                     units);
    uct_cxi_fc_pb_sent(ep, iface, fcbits);

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      AM, SHORT, sizeof(uint64_t) + length);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * ep_send_rndv_hdr_announce
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_send_rndv_hdr_announce -- one-time-per-ep control message
 * carrying {ep_id, md_index, where our rendezvous address table is} to the
 * peer, over the same unrestricted IDC path as uct_cxi_ep_am_short() above,
 * but with UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG set in match_bits instead of a real
 * am_id -- the receiver's AM dispatch (cxi_iface.c) checks that bit before
 * ever calling uct_iface_invoke_am(), routing this to
 * uct_cxi_iface_handle_rndv_hdr_announce() (cxi_tag.c) instead. To the flow
 * control it is an ordinary Active Message (credited, tracked); it is not
 * resent if it is lost, only sent again if the send was refused.
 */
ucs_status_t uct_cxi_ep_send_rndv_hdr_announce(uct_cxi_ep_t *ep,
                                                uint64_t ep_id,
                                                uint8_t md_index)
{
    uct_cxi_iface_t         *iface = uct_cxi_am_ep_iface(ep);
    uct_cxi_rndv_peer_hdr_t  payload;
    unsigned                 units = UCT_CXI_FC_UNITS(sizeof(payload));
    uint64_t                 fcbits;
    ucs_status_t             status;
    int                      credited;

    /* An ordinary Active Message as far as the target is concerned: it uses
     * an AM buffer and an event, and the target hands its credits back like
     * any other's. */
    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM,
                                UCT_CXI_FC_SLOTS_AM, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }
    fcbits = uct_cxi_fc_pb_bits(ep, iface);

    memset(&payload, 0, sizeof(payload));
    payload.ep_id      = ep_id;
    payload.md_index   = md_index;
    payload.table_iova = iface->rdzv.addr_table_mh.iova_offset +
                         (uint64_t)(uintptr_t)iface->rdzv.addr_table;

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_am, ep->dfa_am_idx_ext,
                                 UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG | fcbits, 0,
                                 &payload, sizeof(payload), UCT_CXI_FC_AM,
                                 units, credited, "rndv_hdr_announce");
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                     units);
    uct_cxi_fc_pb_sent(ep, iface, fcbits);
    ucs_debug("cxi TAG [RNDV-HDR-ANNOUNCE] ep=%p ep_id=0x%lx md_index=%u "
             "table_iova=0x%lx", ep, (unsigned long)ep_id,
             (unsigned)md_index, (unsigned long)payload.table_iova);
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
    unsigned             units;
    uint64_t             fcbits;
    ucs_status_t         status;
    int                  credited;
    int                  ret;

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->am.fc)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    /* The length is only known once it is packed, and pack_cb must run once:
     * so ask only for one unit now (any credit at all) and charge the real
     * cost afterwards. Credits may thereby dip below zero by up to one bcopy
     * (max_bcopy bytes), which the byte window's slack absorbs; what matters
     * is that a 1-byte message is never refused for want of room for a big
     * one. */
    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM,
                                UCT_CXI_FC_SLOTS_AM, 1, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return (ssize_t)status;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);
    units  = UCT_CXI_FC_UNITS(length);
    fcbits = uct_cxi_fc_pb_bits(ep, iface);

    desc->op.ep      = ep;
    desc->op.comp    = NULL;
    desc->op.handler = uct_cxi_am_bcopy_comp;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode       = C_CMD_PUT;
        cmd.index_ext            = ep->dfa_am_idx_ext;
        cmd.lac                  = desc->lac;
        cmd.event_send_disable     = 1;
        cmd.event_success_disable = 0;
        cmd.restricted           = 0;
        cmd.initiator            = iface->match_id;
        cmd.eq                   = iface->tx_eq.evtq->eqn;
        cmd.dfa                  = ep->dfa_am;
        cmd.match_bits           = (uint64_t)id | fcbits;
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
        uct_cxi_tx_emit_error(ep, "ep_am_bcopy", ret);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                     units);
    uct_cxi_op_fc_set(&desc->op, credited, UCT_CXI_FC_AM,
                      UCT_CXI_FC_SLOTS_AM, units);
    uct_cxi_fc_pb_sent(ep, iface, fcbits);

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
    size_t                wire_len;
    unsigned              units;
    uint64_t              fcbits;
    ucs_status_t          status;
    int                   contiguous;
    int                   credited;
    int                   ret;

    UCT_CHECK_LENGTH(header_length, 0, sizeof(uint64_t), "am_zcopy header");
    UCT_CHECK_LENGTH(header_length + iov_length, 0, iface->am.max_zcopy,
                     "am_zcopy total");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->am.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    /* What the target will see as the message's length, hence what it will
     * hand back: the header counts only when it travels in the payload. */
    contiguous = (header_length > 0) &&
                 ((const uint8_t *)header + header_length ==
                  (const uint8_t *)iov[0].buffer);
    wire_len   = contiguous ? (header_length + iov_length) : iov_length;
    units      = UCT_CXI_FC_UNITS(wire_len);

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM,
                                UCT_CXI_FC_SLOTS_AM, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }
    fcbits = uct_cxi_fc_pb_bits(ep, iface);

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = comp;
    op->handler = NULL;

    {
        struct c_full_dma_cmd cmd = {};

        cmd.command.opcode        = C_CMD_PUT;
        cmd.index_ext             = ep->dfa_am_idx_ext;
        cmd.lac                   = memh->cxi_md->lac;
        cmd.event_send_disable    = 1;
        cmd.event_success_disable = 0;
        cmd.restricted            = 0;
        cmd.initiator             = iface->match_id;
        cmd.eq                    = iface->tx_eq.evtq->eqn;
        cmd.dfa                   = ep->dfa_am;
        cmd.remote_offset         = 0;
        cmd.user_ptr              = (uint64_t)(uintptr_t)op;

        if (contiguous) {
            cmd.match_bits  = (uint64_t)id | fcbits;
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)header;
            cmd.request_len = (uint32_t)(header_length + iov_length);
        } else if (header_length > 0) {
            cmd.match_bits  = (uint64_t)id | UCT_CXI_AM_HDR_FLAG | fcbits;
            cmd.header_data = 0;
            memcpy(&cmd.header_data, header, header_length);
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)iov[0].buffer;
            cmd.request_len = (uint32_t)iov_length;
        } else {
            cmd.match_bits  = (uint64_t)id | fcbits;
            cmd.local_addr  = memh->iova_offset +
                              (uint64_t)(uintptr_t)iov[0].buffer;
            cmd.request_len = (uint32_t)iov_length;
        }

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        uct_cxi_tx_emit_error(ep, "ep_am_zcopy", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                     units);
    uct_cxi_op_fc_set(op, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                      units);
    uct_cxi_fc_pb_sent(ep, iface, fcbits);

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t),
                      AM, ZCOPY, header_length + iov_length);
    return UCS_INPROGRESS;
}
