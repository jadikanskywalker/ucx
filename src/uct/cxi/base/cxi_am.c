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
#include "config.h"
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


/* Reserve credits for an AM of \a units; get the credits owed to the peer */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_am_reserve(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, unsigned units,
                   int *credited_p, uint64_t *fcbits_p)
{
    ucs_status_t status;

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                                units, credited_p);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    *fcbits_p = uct_cxi_fc_pb_bits(ep, iface);
    return UCS_OK;
}

/* Charge an AM that has been rung and mark its piggybacked credits as sent */
static UCS_F_ALWAYS_INLINE void
uct_cxi_am_charge(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, int credited,
                  unsigned units, uint64_t fcbits)
{
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM, units);
    uct_cxi_fc_pb_sent(ep, iface, fcbits);
}

/* The fields of the DMA PUT to the AM PTE common to bcopy and zcopy */
static UCS_F_ALWAYS_INLINE void
uct_cxi_am_dma_init(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, uint8_t lac,
                    void *user_ptr, struct c_full_dma_cmd *cmd)
{
    cmd->command.opcode     = C_CMD_PUT;
    cmd->index_ext          = ep->dfa_am_idx_ext;
    cmd->lac                = lac;
    cmd->event_send_disable = 1;
    cmd->initiator          = iface->match_id;
    cmd->eq                 = iface->tx_eq.evtq->eqn;
    cmd->dfa                = ep->dfa_am;
    cmd->user_ptr           = (uint64_t)(uintptr_t)user_ptr;
}

/*
 * Send [header(8B)|payload] (payload up to 184 B) as one inline IDC message.
 * The caller's buffers are reusable on return.
 */
ucs_status_t uct_cxi_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t header,
                                 const void *payload, unsigned length)
{
    uct_cxi_ep_t *ep       = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    unsigned units         = UCT_CXI_FC_UNITS(sizeof(header) + length);
    uint8_t buf[C_MAX_IDC_PAYLOAD_UNR];
    uint64_t fcbits;
    ucs_status_t status;
    int credited;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_UNR - sizeof(header),
                     "am_short");

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    status = uct_cxi_am_reserve(ep, iface, units, &credited, &fcbits);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    memcpy(buf, &header, sizeof(header));
    memcpy(buf + sizeof(header), payload, length);

    ucs_trace("cxi IDC_SEND: am_id=%u total_len=%zu "
              "nid=%u pid=%u idx_ext=%u "
              "wp32=%lu hw_wp32=%lu",
              (unsigned)id, sizeof(header) + length, ep->rem_nid, ep->rem_pid,
              (unsigned)ep->dfa_am_idx_ext, (unsigned long)iface->tx.cmdq->wp32,
              (unsigned long)iface->tx.cmdq->hw_wp32);

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_am, ep->dfa_am_idx_ext,
                                 (uint64_t)id | fcbits, 0, buf,
                                 sizeof(header) + length, UCT_CXI_FC_AM, units,
                                 credited, "am_short");
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_am_charge(ep, iface, credited, units, fcbits);

    UCT_TL_EP_STAT_OP(&ep->super, AM, SHORT, sizeof(header) + length);
    return UCS_OK;
}

/*
 * Once per ep, send {ep_id, md_index, rendezvous address table} to the peer as
 * an AM with UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG in match_bits, which the receiver
 * routes to uct_cxi_iface_handle_rndv_hdr_announce(). Credited and tracked
 * like any AM (the target uses an AM buffer and an event, and hands the
 * credits back); resent only if the send was refused.
 */
ucs_status_t uct_cxi_ep_send_rndv_hdr_announce(uct_cxi_ep_t *ep, uint64_t ep_id,
                                               uint8_t md_index)
{
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    unsigned units         = UCT_CXI_FC_UNITS(sizeof(uct_cxi_rndv_peer_hdr_t));
    uct_cxi_rndv_peer_hdr_t payload;
    uint64_t fcbits;
    ucs_status_t status;
    int credited;

    status = uct_cxi_am_reserve(ep, iface, units, &credited, &fcbits);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    /* The padding goes on the wire */
    memset(&payload, 0, sizeof(payload));
    payload.ep_id      = ep_id;
    payload.md_index   = md_index;
    payload.table_iova = uct_cxi_mem_iova(&iface->rdzv.addr_table_mh,
                                          iface->rdzv.addr_table);

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_am, ep->dfa_am_idx_ext,
                                 UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG | fcbits, 0,
                                 &payload, sizeof(payload), UCT_CXI_FC_AM,
                                 units, credited, "rndv_hdr_announce");
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_am_charge(ep, iface, credited, units, fcbits);
    ucs_debug("cxi TAG [RNDV-HDR-ANNOUNCE] ep=%p ep_id=0x%lx md_index=%u "
              "table_iova=0x%lx",
              ep, (unsigned long)ep_id, (unsigned)md_index,
              (unsigned long)payload.table_iova);
    return UCS_OK;
}

/* AM via a bounce buffer from desc_pool. Returns the packed length. */
ssize_t uct_cxi_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                            uct_pack_callback_t pack_cb, void *arg,
                            unsigned flags)
{
    uct_cxi_ep_t *ep          = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface    = uct_cxi_ep_iface(ep);
    struct c_full_dma_cmd cmd = {};
    uct_cxi_send_desc_t *desc;
    size_t length;
    unsigned units;
    uint64_t fcbits;
    ucs_status_t status;
    int credited;

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    /* The length is known only after packing, which must run once: reserve one
     * unit now and charge the real cost afterwards (credits may dip below zero
     * by up to one bcopy). */
    status = uct_cxi_am_reserve(ep, iface, 1, &credited, &fcbits);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);
    units  = UCT_CXI_FC_UNITS(length);

    uct_cxi_send_op_set(&desc->op, ep, NULL, uct_cxi_send_desc_put_comp);

    /* remote_offset stays 0: the NIC places at its managed write pointer */
    uct_cxi_am_dma_init(ep, iface, desc->lac, desc, &cmd);
    cmd.match_bits  = (uint64_t)id | fcbits;
    cmd.local_addr  = desc->iova;
    cmd.request_len = (uint32_t)length;

    ucs_trace("cxi DMA_PUT_SEND: am_id=%u len=%u "
              "nid=%u pid=%u idx_ext=%u eq=%u lac=%u "
              "local_addr=0x%lx wp32=%lu hw_wp32=%lu",
              (unsigned)id, cmd.request_len, ep->rem_nid, ep->rem_pid,
              (unsigned)ep->dfa_am_idx_ext, (unsigned)cmd.eq, (unsigned)cmd.lac,
              (unsigned long)cmd.local_addr,
              (unsigned long)iface->tx.cmdq->wp32,
              (unsigned long)iface->tx.cmdq->hw_wp32);

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_am_bcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(desc);
        return status;
    }

    uct_cxi_am_charge(ep, iface, credited, units, fcbits);
    uct_cxi_op_fc_set(&desc->op, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                      units);

    UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, length);
    return length;
}

/*
 * AM straight from the caller's registered buffer (no send-side gather). A
 * header contiguous with the payload goes in one DMA; otherwise it travels
 * in cmd.header_data with UCT_CXI_AM_HDR_FLAG set, and the receiver prepends
 * it to the payload. The payload plus 8 bytes must fit one receive buffer.
 */
ucs_status_t uct_cxi_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                 unsigned header_length, const uct_iov_t *iov,
                                 size_t iovcnt, unsigned flags,
                                 uct_completion_t *comp)
{
    uct_cxi_ep_t *ep           = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface     = uct_cxi_ep_iface(ep);
    uct_cxi_mem_handle_t *memh = (uct_cxi_mem_handle_t*)iov[0].memh;
    size_t iov_length          = uct_iov_get_length(iov);
    struct c_full_dma_cmd cmd  = {};
    uct_cxi_send_op_t *op;
    size_t wire_len;
    unsigned units;
    uint64_t fcbits;
    ucs_status_t status;
    int contiguous;
    int credited;

    UCT_CHECK_LENGTH(header_length, 0, sizeof(uint64_t), "am_zcopy header");
    UCT_CHECK_LENGTH(header_length + iov_length, 0, iface->am.max_zcopy,
                     "am_zcopy total");

    if (uct_cxi_iface_tx_blocked(iface, &iface->am.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    /* What the target will see as the message's length, hence what it will
     * hand back: the header counts only when it travels in the payload. */
    contiguous = (header_length > 0) &&
                 ((const uint8_t*)header + header_length ==
                  (const uint8_t*)iov[0].buffer);
    wire_len   = contiguous ? (header_length + iov_length) : iov_length;
    units      = UCT_CXI_FC_UNITS(wire_len);

    status = uct_cxi_am_reserve(ep, iface, units, &credited, &fcbits);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    uct_cxi_send_op_set(op, ep, comp, NULL);

    uct_cxi_am_dma_init(ep, iface, memh->cxi_md->lac, op, &cmd);
    cmd.match_bits  = (uint64_t)id | fcbits;
    cmd.local_addr  = uct_cxi_mem_iova(memh,
                                       contiguous ? header : iov[0].buffer);
    cmd.request_len = (uint32_t)wire_len;

    if (!contiguous && (header_length > 0)) {
        cmd.match_bits |= UCT_CXI_AM_HDR_FLAG;
        memcpy(&cmd.header_data, header, header_length);
    }

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "ep_am_zcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(op);
        return status;
    }

    uct_cxi_am_charge(ep, iface, credited, units, fcbits);
    uct_cxi_op_fc_set(op, credited, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM, units);

    UCT_TL_EP_STAT_OP(&ep->super, AM, ZCOPY, header_length + iov_length);
    return UCS_INPROGRESS;
}
