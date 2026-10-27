/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI Active Message declarations (see cxi_am.c).
 */

#ifndef UCT_CXI_AM_H
#define UCT_CXI_AM_H

#include "cxi_ep.h"
#include <uct/api/uct.h>

/* Bit 5 of match_bits: header_data carries an out-of-band AM header.
 * Set by am_zcopy when header and IOV payload are non-contiguous.
 * Bits 0-4 = am_id (0-31). */
#define UCT_CXI_AM_HDR_FLAG (1ULL << 5)

/* Bit 6 of match_bits: a transport-internal rendezvous-header announce, not a
 * user AM. Disjoint from am_id (bits 0-4) and UCT_CXI_AM_HDR_FLAG (bit 5). */
#define UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG (1ULL << 6)

ucs_status_t uct_cxi_ep_am_short(uct_ep_h ep, uint8_t id, uint64_t header,
                                 const void *payload, unsigned length);

ssize_t uct_cxi_ep_am_bcopy(uct_ep_h ep, uint8_t id,
                            uct_pack_callback_t pack_cb, void *arg,
                            unsigned flags);

ucs_status_t uct_cxi_ep_am_zcopy(uct_ep_h ep, uint8_t id, const void *header,
                                 unsigned header_length, const uct_iov_t *iov,
                                 size_t iovcnt, unsigned flags,
                                 uct_completion_t *comp);

/*
 * Once per ep, send the constant {ep_id, md_index} halves of UCP's rendezvous
 * header (uct_cxi_rndv_peer_hdr_t) as an AM with the announce flag.
 */
ucs_status_t uct_cxi_ep_send_rndv_hdr_announce(uct_cxi_ep_t *ep, uint64_t ep_id,
                                               uint8_t md_index);

#endif /* UCT_CXI_AM_H */
