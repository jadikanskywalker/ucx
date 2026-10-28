/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI flow-control peers (cxi_peer.c): the interface of the handshake and
 * the credit accounting. Included only by cxi_iface.h, after uct_cxi_iface_t.
 */

#ifndef UCT_CXI_PEER_H
#define UCT_CXI_PEER_H

#include <ucs/sys/compiler_def.h>


BEGIN_C_DECLS

ucs_status_t
uct_cxi_fc_init(uct_cxi_iface_t *iface, const uct_cxi_iface_config_t *config,
                uint32_t slot_window,
                const uint32_t unit_window[UCT_CXI_FC_NUM_CLASSES]);
void uct_cxi_fc_cleanup(uct_cxi_iface_t *iface);

/** Find or create the record of remote iface (\a nid, \a pid); NULL on no
 *  memory. */
uct_cxi_peer_t *
uct_cxi_peer_get(uct_cxi_iface_t *iface, uint32_t nid, uint32_t pid);

/** Start \a peer's handshake, unless one has been started or finished. */
void uct_cxi_peer_connect(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** A C_EVENT_PUT on the control PTE. */
void uct_cxi_iface_handle_ctrl_msg(uct_cxi_iface_t *iface,
                                   const union c_event *event);

/** The TX completion of a control request, \a req from the user_ptr. */
void uct_cxi_iface_ctrl_tx_done(uct_cxi_iface_t *iface, uct_cxi_ctrl_req_t *req,
                                const union c_event *event);

/** Send the GRANTs that are waiting, as far as there is room. */
void uct_cxi_fc_flush_grants(uct_cxi_iface_t *iface);

/** The peer record for initiator \a process, or NULL (a sender without flow
 *  control). Refills the one-entry cache. */
uct_cxi_peer_t *
uct_cxi_fc_rx_peer_slow(uct_cxi_iface_t *iface, uint32_t process);

/** Credits piggybacked on an Active Message from \a peer (\a match_bits). */
void uct_cxi_fc_apply_piggyback(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                                uint64_t match_bits);

/** We owe \a peer many credits: send a GRANT now, or when we can. */
void uct_cxi_fc_grant_wanted(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Make runnable the endpoints of \a peer that were waiting for credits. */
void uct_cxi_peer_resume(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Take back credits the target will never return (send lost or untracked). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_reclaim(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer, unsigned cls,
                   unsigned slots, unsigned units)
{
    peer->tx.avail_slots      += (int32_t)slots;
    peer->tx.avail_units[cls] += (int32_t)units;
    peer->tx.used_slots       -= slots;
    peer->tx.used_units[cls]  -= units;

    if (ucs_unlikely(peer->blocked != NULL)) {
        uct_cxi_peer_resume(iface, peer);
    }
}

/** Give back the credits of a send to \a ep's peer that never arrived. */
void uct_cxi_fc_refund(uct_cxi_iface_t *iface, struct uct_cxi_ep *ep,
                       unsigned cls, unsigned slots, unsigned units);

/** Forget what we told \a peer that it may not have received. */
void uct_cxi_fc_resync(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Park \a ep, whose pending queue waits for credits, on its peer. */
void uct_cxi_fc_block_ep(struct uct_cxi_ep *ep);

/** Forget \a ep (being destroyed) wherever it is parked. */
void uct_cxi_fc_unblock_ep(struct uct_cxi_ep *ep);

END_C_DECLS

/** The record of the sender of the AM just received, or NULL (uncharged). */
static UCS_F_ALWAYS_INLINE uct_cxi_peer_t *
uct_cxi_fc_rx_peer(uct_cxi_iface_t *iface, uint32_t process)
{
    if (ucs_likely((iface->fc.rx_cache_peer != NULL) &&
                   (iface->fc.rx_cache_key == process))) {
        return iface->fc.rx_cache_peer;
    }

    return uct_cxi_fc_rx_peer_slow(iface, process);
}

/** A message from \a peer was processed: its credits are ours to return. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_rx_done(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer, unsigned cls,
                   unsigned slots, uint32_t mlength)
{
    uct_cxi_fc_rx_t *rx = &peer->rx;

    rx->ret_slots      += slots;
    rx->ret_units[cls] += UCT_CXI_FC_UNITS(mlength);

    if (ucs_unlikely(((uint32_t)(rx->ret_slots - rx->adv_slots) >=
                      iface->fc.grant_slots) ||
                     ((uint32_t)(rx->ret_units[cls] - rx->adv_units[cls]) >=
                      iface->fc.grant_units[cls]))) {
        uct_cxi_fc_grant_wanted(iface, peer);
    }
}

#endif /* UCT_CXI_PEER_H */
