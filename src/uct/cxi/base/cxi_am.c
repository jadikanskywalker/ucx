/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI Active Message operations: am_short, am_bcopy, am_zcopy.
 *
 * TX: each sends an unrestricted message to the remote AM PTE (ep->dfa_am),
 * counted against its ep and the TX queue until its completion, and charged
 * against the credits the target granted (cxi_fc.h).
 *   short: an IDC message, no descriptor; its completion carries the ep and
 *          the charge in its user_ptr (cxi_ep.h).
 *   bcopy: a desc from desc_pool, packed, then a C_CMD_PUT; freed on the ACK.
 *   zcopy: a C_CMD_PUT from the caller's registered buffer.
 *
 * RX: progress sees C_EVENT_PUT on the AM list, finds the ring buffer from
 * buffer_id and calls uct_iface_invoke_am. The ring is managed in
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

/* AM bcopy completion: just return the descriptor. */
static void uct_cxi_am_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    ucs_mpool_put((uct_cxi_send_desc_t *)op);
}


/* -------------------------------------------------------------------------
 * ep_am_short
 * -------------------------------------------------------------------------
 */

/*
 * Send [header(8B)|payload] (payload up to 184 B) as one inline IDC message.
 * The caller's buffers are reusable on return.
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

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
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
 * Once per ep, send {ep_id, md_index, rendezvous address table} to the peer as
 * an AM with UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG in match_bits, which the receiver
 * routes to uct_cxi_iface_handle_rndv_hdr_announce(). Credited and tracked
 * like any AM; resent only if the send was refused.
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

/* AM via a bounce buffer from desc_pool. Returns the packed length. */
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

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    /* The length is known only after packing, which must run once: reserve one
     * unit now and charge the real cost afterwards (credits may dip below zero
     * by up to one bcopy). */
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
 * AM straight from the caller's registered buffer (no send-side gather). A
 * header contiguous with the payload goes in one DMA; otherwise it travels
 * in cmd.header_data with UCT_CXI_AM_HDR_FLAG set, and the receiver prepends
 * it to the payload. The payload plus 8 bytes must fit one receive buffer.
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

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
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
