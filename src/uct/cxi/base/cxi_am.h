/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI Active Message operation declarations.
 *
 * AM short: c_cstate_cmd (restricted=0) + c_idc_msg_hdr carrying
 *   [uint64_t header][payload] ≤ C_MAX_IDC_PAYLOAD_UNR = 192 B total.
 *   The 8-byte UCT header is packed inline before the user payload so the
 *   receiver gets a single contiguous buffer directly from rx_buf.
 *
 * AM bcopy: c_full_dma_cmd (restricted=0) to the remote AM OVERFLOW LE;
 *   the desc_pool bounce buffer is reused (same as RMA put_bcopy).
 *
 * RX: iface_progress handles C_EVENT_PUT from the AM PTE's OVERFLOW LE and
 *   dispatches to the callback registered via uct_iface_set_am_handler.
 */

#ifndef UCT_CXI_AM_H
#define UCT_CXI_AM_H

#include "cxi_ep.h"
#include <uct/api/uct.h>

/* Bit 5 of match_bits: header_data carries an out-of-band AM header.
 * Set by am_zcopy when header and IOV payload are non-contiguous.
 * Bits 0-4 = am_id (0-31). */
#define UCT_CXI_AM_HDR_FLAG  (1ULL << 5)

/* Bit 6 of match_bits: this AM-PTE arrival is a transport-internal
 * rendezvous-header announce (see uct_cxi_ep_send_rndv_hdr_announce /
 * uct_cxi_iface_handle_rndv_hdr_announce in cxi_tag.c), not a real user AM --
 * route it away from uct_iface_invoke_am() entirely. Disjoint from am_id
 * (bits 0-4, capped at UCT_AM_ID_MAX=32 by the public API's UCT_CHECK_AM_ID)
 * and from UCT_CXI_AM_HDR_FLAG (bit 5), so it can never collide with
 * anything UCP itself sends or registers a handler for. */
#define UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG  (1ULL << 6)

ucs_status_t uct_cxi_ep_am_short(uct_ep_h ep, uint8_t id, uint64_t header,
                                  const void *payload, unsigned length);

ssize_t uct_cxi_ep_am_bcopy(uct_ep_h ep, uint8_t id,
                             uct_pack_callback_t pack_cb, void *arg,
                             unsigned flags);

ucs_status_t uct_cxi_ep_am_zcopy(uct_ep_h ep, uint8_t id,
                                  const void *header, unsigned header_length,
                                  const uct_iov_t *iov, size_t iovcnt,
                                  unsigned flags, uct_completion_t *comp);

/*
 * uct_cxi_ep_send_rndv_hdr_announce -- one-time-per-ep control message
 * carrying the constant-for-the-life-of-the-ep {ep_id, md_index} halves of
 * UCP's rendezvous header (see cxi_ep.h's rndv_hdr_announced and
 * uct_ep_tag_rndv_zcopy in cxi_tag.c). Mirrors uct_cxi_ep_am_short's own
 * fire-and-forget IDC-send mechanism, but targets the reserved
 * UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG match_bits instead of a real am_id, and
 * carries a uct_cxi_rndv_peer_hdr_t (cxi_iface.h) as its payload.
 */
ucs_status_t uct_cxi_ep_send_rndv_hdr_announce(uct_cxi_ep_t *ep,
                                                uint64_t ep_id,
                                                uint8_t md_index);

#endif /* UCT_CXI_AM_H */
