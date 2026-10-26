/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI connected-endpoint flow control: peer records and the control channel
 * handshake. See cxi_fc.h for the protocol.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"
#include "cxi_ep.h"

/* Normally only built when flow control is enabled (see Makefile.am); the
 * guard keeps a build that merely defines UCT_CXI_DISABLE_FC working too. */
#ifndef UCT_CXI_DISABLE_FC

#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>

#include <string.h>


/* Plain host memory: control requests are only ever read by software. */
static ucs_mpool_ops_t uct_cxi_fc_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL,
    .obj_str       = NULL
};


/* The NID and PID of \a peer, and where its control PTE is: all worked out
 * from the key (they are needed to send a control message or to log, never per
 * Active Message), so the record does not hold them. */
static UCS_F_ALWAYS_INLINE uint32_t
uct_cxi_peer_nid(uct_cxi_iface_t *iface, const uct_cxi_peer_t *peer)
{
    return CXI_MATCH_ID_EP(uct_cxi_iface_md(iface)->pid_bits, peer->key);
}

static UCS_F_ALWAYS_INLINE uint32_t
uct_cxi_peer_pid(uct_cxi_iface_t *iface, const uct_cxi_peer_t *peer)
{
    return CXI_MATCH_ID_PID(uct_cxi_iface_md(iface)->pid_bits, peer->key);
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_peer_ctrl_dfa(uct_cxi_iface_t *iface, const uct_cxi_peer_t *peer,
                      union c_fab_addr *dfa, uint8_t *idx_ext)
{
    cxi_build_dfa(uct_cxi_peer_nid(iface, peer), uct_cxi_peer_pid(iface, peer),
                  uct_cxi_iface_md(iface)->pid_bits, UCT_CXI_PTE_CTRL, dfa,
                  idx_ext);
}

static void uct_cxi_fc_grant_timer(ucs_wtimer_t *timer);

/*
 * Set \a timer on the wheel to go off in \a delay (not less than a slot, and
 * the wheel's own cap is a little over the longest delay used). The wheel is
 * only swept while it has timers, so when this is the first it may be far
 * behind: bring it up to date before anything is set on it.
 */
static void uct_cxi_fc_timer_add(uct_cxi_iface_t *iface, ucs_wtimer_t *timer,
                                 ucs_time_t delay)
{
    ucs_twheel_t *twheel = &iface->fc.twheel;

    if (ucs_twheel_is_empty(twheel)) {
        ucs_twheel_sweep(twheel, ucs_get_time());
    }
    ucs_wtimer_add(twheel, timer, ucs_max(delay, twheel->res));
}
static void uct_cxi_fc_queue_grant(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/* -------------------------------------------------------------------------
 * Interface-level state
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_fc_init(uct_cxi_iface_t *iface,
                             const uct_cxi_iface_config_t *config,
                             uint32_t slot_window,
                             const uint32_t unit_window[UCT_CXI_FC_NUM_CLASSES])
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    ucs_mpool_params_t  mp_params;
    ucs_status_t        status;

    unsigned            max_units[UCT_CXI_FC_NUM_CLASSES] = {
        [UCT_CXI_FC_AM]  = UCT_CXI_FC_UNITS(iface->am.max_msg),
        [UCT_CXI_FC_TAG] = UCT_CXI_FC_UNITS(iface->tag.max_msg)
    };
    double              thresh    = ucs_max(0.01, ucs_min(1.0,
                                                config->fc_grant_thresh));
    unsigned            cls;

    memset(fc, 0, sizeof(*fc));
    fc->enabled         = config->fc_enable;
    fc->ctrl.ptn        = UINT16_MAX; /* matches no PTE until one is opened */
    fc->connect_timeout = ucs_time_from_sec(config->fc_connect_timeout);
    fc->slot_window     = slot_window;
    fc->pb_shift[0]     = uct_cxi_fc_pb_shift(slot_window,
                                              UCT_CXI_FC_PB_SLOT_BITS);

    /* Hand credits back once this much is owed. The byte threshold leaves room
     * for one maximum-size message: a sender blocked for lack of units has
     * more than window - max_units outstanding, and once the target has
     * processed all of it, that is more than the threshold, so a grant is
     * always on its way. A class with no pool never asks for one. */
    fc->grant_slots = ucs_max(1u, (uint32_t)(fc->slot_window * thresh));
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        fc->unit_window[cls] = unit_window[cls];
        fc->pb_shift[1 + cls] = uct_cxi_fc_pb_shift(unit_window[cls],
                                                    UCT_CXI_FC_PB_UNIT_BITS);
        fc->grant_units[cls] = (unit_window[cls] == 0) ? UINT32_MAX :
                ucs_max(1u, ucs_min((uint32_t)(unit_window[cls] * thresh),
                                    unit_window[cls] - max_units[cls]));
    }

    /* Random per interface instance, so a peer can tell a restarted process
     * from the one it handshook with before. Never 0. */
    fc->epoch = (uint32_t)ucs_generate_uuid((uintptr_t)iface);
    if (fc->epoch == 0) {
        fc->epoch = 1;
    }

    kh_init_inplace(uct_cxi_peer_hash, &fc->peers);
    ucs_list_head_init(&fc->grants);
    ucs_wtimer_init(&fc->grant_timer, uct_cxi_fc_grant_timer);

    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_ctrl_req_t);
    mp_params.elems_per_chunk = 32;
    mp_params.ops             = &uct_cxi_fc_mpool_ops;
    mp_params.name            = "cxi-ctrl-req";
    status = ucs_mpool_init(&mp_params, &fc->ctrl_req_pool);
    if (status != UCS_OK) {
        goto err_peers;
    }

    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_peer_conn_t);
    mp_params.elems_per_chunk = 32;
    mp_params.ops             = &uct_cxi_fc_mpool_ops;
    mp_params.name            = "cxi-peer-conn";
    status = ucs_mpool_init(&mp_params, &fc->conn_pool);
    if (status != UCS_OK) {
        goto err_ctrl_pool;
    }

    /* The resolution is the shortest retry delay: a timer can not be set for
     * less than one slot. */
    status = ucs_twheel_init(&fc->twheel,
                             ucs_time_from_usec(UCT_CXI_CTRL_RETRY_BASE_US),
                             ucs_get_time());
    if (status != UCS_OK) {
        goto err_conn_pool;
    }
    return UCS_OK;

err_conn_pool:
    ucs_mpool_cleanup(&fc->conn_pool, 1);
err_ctrl_pool:
    ucs_mpool_cleanup(&fc->ctrl_req_pool, 1);
err_peers:
    kh_destroy_inplace(uct_cxi_peer_hash, &fc->peers);
    return status;
}

void uct_cxi_fc_cleanup(uct_cxi_iface_t *iface)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    uct_cxi_peer_t     *peer;

    ucs_wtimer_remove(&fc->twheel, &fc->grant_timer);
    kh_foreach_value(&fc->peers, peer, {
        if (peer->conn != NULL) {
            ucs_wtimer_remove(&fc->twheel, &peer->conn->timer);
        }
        ucs_free(peer);
    });
    kh_destroy_inplace(uct_cxi_peer_hash, &fc->peers);

    /* A control request still in flight when the interface closes is normal
     * (its completion is simply never processed), and so is a handshake still
     * going: don't report them as leaks. */
    ucs_mpool_cleanup(&fc->ctrl_req_pool, 0);
    ucs_mpool_cleanup(&fc->conn_pool, 0);
    ucs_twheel_cleanup(&fc->twheel);
}


/* -------------------------------------------------------------------------
 * Control PTE
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_iface_open_ctrl_pte(uct_cxi_iface_t *iface,
                                         struct cxil_lni *lni)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    const union c_event *ev;
    struct c_target_cmd  le = {};
    ucs_status_t         status;
    int                  ret;

    if (!fc->enabled) {
        return UCS_OK;
    }

    {
        /* en_flowctrl: when the receive event queue is full the PTE disables
         * itself and the sender sees C_RC_PT_DISABLED, instead of the event
         * being lost -- the only way this PTE can refuse a message, since its
         * list entry holds no buffer. */
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,
            .use_long_event = 1,
            .en_flowctrl    = 1
        };
        ret = cxil_alloc_pte(lni, iface->rx_eq.evtq, &pt_opts, &fc->ctrl.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte CTRL: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    ret = cxil_map_pte(fc->ctrl.pte, iface->domain, (int)UCT_CXI_PTE_CTRL,
                       false, &fc->ctrl.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte CTRL: %s", strerror(-ret));
        goto err_destroy_pte;
    }

    /* Transition the PTE DISABLED -> ENABLED; spin for the STATE_CHANGE. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = fc->ctrl.pte->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(iface->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi CTRL SETSTATE: %d", ret);
            goto err_unmap_pte;
        }
        cxi_cq_ring(iface->tgt.cmdq);

        while (!enabled) {
            while ((ev = cxi_eq_get_event(iface->rx_eq.evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(iface->rx_eq.evtq);
        }
    }

    /* One persistent, zero-length list entry that accepts everything. */
    le.command.opcode          = C_CMD_TGT_APPEND;
    le.ptl_list                = C_PTL_LIST_PRIORITY;
    le.ptlte_index             = fc->ctrl.pte->ptn;
    le.op_put                  = 1;
    le.use_once                = 0;
    le.manage_local            = 0;
    le.event_link_disable      = 1;
    le.event_unlink_disable    = 1;
    le.unexpected_hdr_disable  = 1;
    le.match_id                = CXI_MATCH_ID_ANY;
    le.ignore_bits             = UINT64_MAX;
    le.match_bits              = 0;
    le.start                   = 0;
    le.length                  = 0;
    status = uct_cxi_iface_tgt_post(iface, &le);
    if (status != UCS_OK) {
        ucs_error("cxi CTRL LE APPEND: %s", ucs_status_string(status));
        goto err_unmap_pte;
    }

    fc->ctrl.ptn = fc->ctrl.pte->ptn;
    ucs_debug("cxi CTRL PTE ptn %u enabled", fc->ctrl.ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(fc->ctrl.pte_map);
    fc->ctrl.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(fc->ctrl.pte);
    fc->ctrl.pte = NULL;
    return UCS_ERR_IO_ERROR;
}

void uct_cxi_iface_close_ctrl_pte(uct_cxi_iface_t *iface)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    int                 ret;

    fc->ctrl.ptn = UINT16_MAX;
    if (fc->ctrl.pte_map != NULL) {
        ret = cxil_unmap_pte(fc->ctrl.pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte CTRL failed: %s", strerror(-ret));
        }
        fc->ctrl.pte_map = NULL;
    }
    if (fc->ctrl.pte != NULL) {
        ret = cxil_destroy_pte(fc->ctrl.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte CTRL failed: %s", strerror(-ret));
        }
        fc->ctrl.pte = NULL;
    }
}


/* -------------------------------------------------------------------------
 * Peers
 * -------------------------------------------------------------------------
 */

uct_cxi_peer_t *uct_cxi_peer_get(uct_cxi_iface_t *iface, uint32_t nid,
                                 uint32_t pid)
{
    uct_cxi_md_t   *md  = uct_cxi_iface_md(iface);
    uint32_t        key = CXI_MATCH_ID(md->pid_bits, pid, nid);
    uct_cxi_peer_t *peer;
    khiter_t        iter;
    int             ret;

    iter = kh_get(uct_cxi_peer_hash, &iface->fc.peers, key);
    if (iter != kh_end(&iface->fc.peers)) {
        return kh_value(&iface->fc.peers, iter);
    }

    peer = ucs_calloc(1, sizeof(*peer), "cxi peer");
    if (peer == NULL) {
        return NULL;
    }

    peer->key   = key;
    peer->state = UCT_CXI_PEER_DOWN;
    ucs_list_head_init(&peer->grants);

    iter = kh_put(uct_cxi_peer_hash, &iface->fc.peers, key, &ret);
    if (ret < 0) {
        ucs_free(peer);
        return NULL;
    }
    kh_value(&iface->fc.peers, iter) = peer;
    return peer;
}

static uct_cxi_peer_t *uct_cxi_peer_lookup(uct_cxi_iface_t *iface,
                                           uint32_t key)
{
    khiter_t iter = kh_get(uct_cxi_peer_hash, &iface->fc.peers, key);

    return (iter == kh_end(&iface->fc.peers)) ?
           NULL : kh_value(&iface->fc.peers, iter);
}

/* A handshake is over (completed, failed, or not needed): stop resending, and
 * let the sends that were waiting on it run (or fail). */
static void uct_cxi_peer_connected(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                                   unsigned state)
{
    uct_cxi_peer_conn_t *conn = peer->conn;

    peer->state = state;
    if (conn != NULL) {
        ucs_wtimer_remove(&iface->fc.twheel, &conn->timer);
        iface->fc.num_connecting--;
        peer->conn = NULL;
        ucs_mpool_put(conn);
    }
    uct_cxi_peer_resume(iface, peer);
}


/* -------------------------------------------------------------------------
 * Credits
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_fc_reserve_slow(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                                     int *credited_p)
{
    uct_cxi_peer_t *peer = ep->peer;

    *credited_p = 0;
    if (peer == NULL) {
        return UCS_OK;
    }

    switch (peer->state) {
    case UCT_CXI_PEER_LEGACY:
        return UCS_OK; /* no flow control with this peer: not charged */
    case UCT_CXI_PEER_FAILED:
        return UCS_ERR_ENDPOINT_TIMEOUT;
    default:
        /* Handshake still in flight. Not an interface resource: the pending
         * queue waits for the CREP, which resumes it (see peer_connected). */
        iface->tx.credit_block = 1;
        return UCS_ERR_NO_RESOURCE;
    }
}

void uct_cxi_fc_block_ep(uct_cxi_ep_t *ep)
{
    if (!ep->fc_listed) {
        ep->next_blocked   = ep->peer->blocked;
        ep->peer->blocked  = ep;
        ep->fc_listed      = 1;
    }
}

void uct_cxi_fc_unblock_ep(uct_cxi_ep_t *ep)
{
    uct_cxi_ep_t **link;

    if (!ep->fc_listed) {
        return;
    }

    for (link = &ep->peer->blocked; *link != NULL;
         link = &(*link)->next_blocked) {
        if (*link == ep) {
            *link = ep->next_blocked;
            break;
        }
    }
    ep->fc_listed = 0;
}

void uct_cxi_peer_resume(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    uct_cxi_ep_t *ep = peer->blocked;
    uct_cxi_ep_t *next;

    peer->blocked = NULL;
    for (; ep != NULL; ep = next) {
        next           = ep->next_blocked;
        ep->fc_listed  = 0;
        ucs_arbiter_group_schedule(&iface->tx.arbiter, &ep->arb_group);
    }
}

/* Apply a cumulative "processed so far" counter from a peer: \a wire is the
 * peer's full counter, truncated to \a bits bits. Spend nothing new if it is
 * not ahead of what was last applied (a duplicate or reordered grant). */
static UCS_F_ALWAYS_INLINE int32_t
uct_cxi_fc_grant_delta(uint32_t wire, uint32_t last, unsigned bits)
{
    unsigned shift = 32 - bits;

    return (int32_t)((wire - last) << shift) >> shift;
}

/*
 * Apply one cumulative counter from a peer: \a wire is the low \a bits bits
 * of the peer's counter in granules of 2^\a shift, and \a *last the whole
 * counter as last applied. Nothing is added if the wire value is not ahead of
 * it (a duplicate or reordered grant); otherwise the counter moves forward
 * to the granule, and \a *avail gets the difference. Returns whether it did.
 */
static UCS_F_ALWAYS_INLINE int
uct_cxi_fc_apply_counter(uint32_t *last, int32_t *avail, uint32_t wire,
                         unsigned bits, unsigned shift)
{
    uint32_t last_granules = *last >> shift;
    int32_t  d             = uct_cxi_fc_grant_delta(wire, last_granules, bits);
    uint32_t counter;

    if (d <= 0) {
        return 0;
    }

    counter = (last_granules + d) << shift;
    *avail += (int32_t)(counter - *last);
    *last   = counter;
    return 1;
}

/* The counters of a grant: \a slots, and the space of each class in \a
 * units. \a shift is the granule of each (NULL: counted exactly). */
static void uct_cxi_fc_apply_grant(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                                   uint32_t slots,
                                   const uint32_t units[UCT_CXI_FC_NUM_CLASSES],
                                   unsigned slot_bits, unsigned unit_bits,
                                   const uint8_t *shift)
{
    int      granted;
    unsigned cls;

    granted = uct_cxi_fc_apply_counter(&peer->tx.ret_slots,
                                       &peer->tx.avail_slots, slots, slot_bits,
                                       (shift != NULL) ? shift[0] : 0);
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        granted |= uct_cxi_fc_apply_counter(&peer->tx.ret_units[cls],
                                            &peer->tx.avail_units[cls],
                                            units[cls], unit_bits,
                                            (shift != NULL) ? shift[1 + cls] :
                                                              0);
    }

    if (granted && (peer->blocked != NULL)) {
        uct_cxi_peer_resume(iface, peer);
    }
}

void uct_cxi_fc_apply_piggyback(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                                uint64_t match_bits)
{
    uint32_t units[UCT_CXI_FC_NUM_CLASSES];
    unsigned cls;

    /* Before the handshake completes we do not know the peer's epoch, and
     * have no credits to add to. The values are cumulative: the next one
     * carries the same information. */
    if ((peer->state != UCT_CXI_PEER_UP) ||
        (((match_bits >> UCT_CXI_FC_PB_EPOCH_SHIFT) &
          UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_EPOCH_BITS)) !=
         (peer->remote_epoch & UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_EPOCH_BITS)))) {
        return;
    }

    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        units[cls] = (uint32_t)((match_bits >> UCT_CXI_FC_PB_UNIT_SHIFT(cls)) &
                                UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_UNIT_BITS));
    }

    uct_cxi_fc_apply_grant(
            iface, peer,
            (uint32_t)((match_bits >> UCT_CXI_FC_PB_SLOT_SHIFT) &
                       UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_SLOT_BITS)),
            units, UCT_CXI_FC_PB_SLOT_BITS, UCT_CXI_FC_PB_UNIT_BITS,
            peer->pb_shift);
}

void uct_cxi_fc_refund(uct_cxi_iface_t *iface, uct_cxi_ep_t *ep, unsigned cls,
                       unsigned slots, unsigned units)
{
    uct_cxi_peer_t *peer = ep->peer;

    /* The send never reached the target's software, which therefore will
     * never hand its credits back: take them back here. */
    uct_cxi_fc_reclaim(iface, peer, cls, slots, units);

    /* A credit grant may have gone with it. (Only Active Messages carry
     * them.) */
    if (cls == UCT_CXI_FC_AM) {
        uct_cxi_fc_resync(iface, peer);
    }
}

void uct_cxi_fc_resync(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    int due;
    unsigned cls;

    peer->rx.adv_slots = peer->rx.acked_slots;
    due = ((uint32_t)(peer->rx.ret_slots - peer->rx.adv_slots) >=
           iface->fc.grant_slots);

    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        peer->rx.adv_units[cls] = peer->rx.acked_units[cls];
        due |= ((uint32_t)(peer->rx.ret_units[cls] -
                           peer->rx.adv_units[cls]) >=
                iface->fc.grant_units[cls]);
    }

    if (due) {
        uct_cxi_fc_queue_grant(iface, peer);
    }
}

uct_cxi_peer_t *uct_cxi_fc_rx_peer_slow(uct_cxi_iface_t *iface,
                                        uint32_t process)
{
    khiter_t iter = kh_get(uct_cxi_peer_hash, &iface->fc.peers, process);

    if (iter == kh_end(&iface->fc.peers)) {
        return NULL;
    }

    iface->fc.rx_cache_key  = process;
    iface->fc.rx_cache_peer = kh_value(&iface->fc.peers, iter);
    return iface->fc.rx_cache_peer;
}


/* -------------------------------------------------------------------------
 * Control messages
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ctrl_send -- send one zero-payload control message to \a peer's
 * control PTE. It is a send like any other as far as the TX queue goes: it
 * takes one of the iface->tx.max_inflight places until its completion, so
 * UCS_ERR_NO_RESOURCE if there is none free or the command queue is full, and
 * the caller just tries again later (a GRANT from the list of waiting ones, a
 * CREQ from its timer, a CREP when the requester sends its CREQ again).
 */
static ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface,
                                      uct_cxi_peer_t *peer, unsigned type,
                                      uint64_t match_bits, uint64_t header_data,
                                      uint32_t grant_slots,
                                      const uint32_t *grant_units)
{
    uct_cxi_ctrl_req_t  *req;
    union c_fab_addr     dfa;
    uint8_t              idx_ext;
    int                  ret;

    if (iface->tx.outstanding >= iface->tx.max_inflight) {
        return UCS_ERR_NO_RESOURCE;
    }

    req = ucs_mpool_get(&iface->fc.ctrl_req_pool);
    if (req == NULL) {
        return UCS_ERR_NO_RESOURCE;
    }
    req->peer        = peer;
    req->type        = type;
    req->grant_slots = grant_slots;
    if (grant_units != NULL) {
        memcpy(req->grant_units, grant_units, sizeof(req->grant_units));
    } else {
        memset(req->grant_units, 0, sizeof(req->grant_units));
    }
    uct_cxi_peer_ctrl_dfa(iface, peer, &dfa, &idx_ext);

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 0;
        cstate.initiator           = iface->match_id;
        cstate.index_ext           = idx_ext;
        uct_cxi_idc_track_cstate(&cstate, iface);

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa         = dfa;
        hdr.match_bits  = match_bits;
        hdr.header_data = header_data;
        hdr.user_ptr    = (uint64_t)(uintptr_t)req | UCT_CXI_USER_PTR_CTRL;

        ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &hdr, hdr.data, 0);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    iface->tx.outstanding++;
    return UCS_OK;
}

void uct_cxi_iface_ctrl_tx_done(uct_cxi_iface_t *iface, uct_cxi_ctrl_req_t *req,
                                const union c_event *event)
{
    int rc = cxi_event_rc(event);

    iface->tx.outstanding--;
    if (req->type == UCT_CXI_CTRL_GRANT) {
        uct_cxi_peer_t *peer = req->peer;
        unsigned        cls;

        if (rc == C_RC_OK) {
            iface->fc.grant_failures = 0;
            /* Delivered: no need to say it again (a later grant may already
             * have overtaken this one, hence the "only forward" test). */
            if ((int32_t)(req->grant_slots - peer->rx.acked_slots) > 0) {
                peer->rx.acked_slots = req->grant_slots;
            }
            for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
                if ((int32_t)(req->grant_units[cls] -
                              peer->rx.acked_units[cls]) > 0) {
                    peer->rx.acked_units[cls] = req->grant_units[cls];
                }
            }
        } else {
            /* Lost: say it again, along with whatever has accumulated, but
             * not at once: the target may be refusing control messages for
             * a while, and a resend straight away would be refused too. */
            ucs_debug("cxi GRANT to nid 0x%x pid %u failed: rc=%d, resending",
                      uct_cxi_peer_nid(iface, peer),
                      uct_cxi_peer_pid(iface, peer), rc);
            iface->fc.grant_failures++;
            uct_cxi_fc_resync(iface, peer);
        }
        ucs_mpool_put(req);
        return;
    }

    if (ucs_unlikely(rc != C_RC_OK)) {
        if ((rc == C_RC_PTLTE_NOT_FOUND) && (req->type == UCT_CXI_CTRL_CREQ) &&
            ((req->peer->state == UCT_CXI_PEER_DOWN) ||
             (req->peer->state == UCT_CXI_PEER_CREQ_SENT))) {
            /* The target has no control PTE: it does not do flow control. */
            ucs_debug("cxi peer nid 0x%x pid %u has no control channel, "
                      "treating it as a legacy peer",
                      uct_cxi_peer_nid(iface, req->peer),
                      uct_cxi_peer_pid(iface, req->peer));
            uct_cxi_peer_connected(iface, req->peer, UCT_CXI_PEER_LEGACY);
        } else {
            /* A CREQ is resent until answered and a lost CREP is answered
             * by the next CREQ, so nothing to do here. */
            ucs_debug("cxi control message %u to nid 0x%x pid %u failed: rc=%d",
                      req->type, uct_cxi_peer_nid(iface, req->peer),
                      uct_cxi_peer_pid(iface, req->peer), rc);
        }
    }

    ucs_mpool_put(req);
}

void uct_cxi_iface_handle_ctrl_msg(uct_cxi_iface_t *iface,
                                   const union c_event *event)
{
    uct_cxi_md_t   *md      = uct_cxi_iface_md(iface);
    uint64_t        mb      = event->tgt_long.match_bits;
    uint64_t        hd      = event->tgt_long.header_data;
    uint32_t        process = event->tgt_long.initiator.initiator.process;
    uint32_t        units[UCT_CXI_FC_NUM_CLASSES];
    uct_cxi_peer_t *peer;
    unsigned        cls;

    if (ucs_unlikely(UCT_CXI_CTRL_VER(mb) != UCT_CXI_CTRL_VERSION)) {
        ucs_debug("cxi ignoring control message with version %u",
                  UCT_CXI_CTRL_VER(mb));
        return;
    }

    switch (UCT_CXI_CTRL_TYPE(mb)) {
    case UCT_CXI_CTRL_CREQ:
        /* The requester's identity is the event's initiator: create its
         * record if this is the first we hear of it (without starting a
         * handshake of our own: each direction is independent). */
        peer = uct_cxi_peer_get(iface, CXI_MATCH_ID_EP(md->pid_bits, process),
                                CXI_MATCH_ID_PID(md->pid_bits, process));
        if (peer == NULL) {
            ucs_error("cxi no memory for a peer record, dropping CREQ");
            return;
        }
        if ((peer->rx_epoch != 0) && (peer->rx_epoch != (uint32_t)hd)) {
            /* The requester restarted: what we owed its previous incarnation
             * means nothing to this one. */
            memset(&peer->rx, 0, sizeof(peer->rx));
        }
        peer->rx_epoch = (uint32_t)hd;

        /* Fire and forget: if this reply is lost, the requester resends its
         * CREQ and gets another. */
        (void)uct_cxi_ctrl_send(
                iface, peer, UCT_CXI_CTRL_CREP,
                UCT_CXI_CTRL_MATCH(UCT_CXI_CTRL_CREP, iface->fc.epoch,
                                   (uint32_t)hd),
                UCT_CXI_CREP_PACK(iface->fc.slot_window,
                                  iface->fc.unit_window[UCT_CXI_FC_AM],
                                  iface->fc.unit_window[UCT_CXI_FC_TAG]),
                0, NULL);
        break;

    case UCT_CXI_CTRL_CREP:
        peer = uct_cxi_peer_lookup(iface, process);
        if ((peer == NULL) ||
            ((peer->state != UCT_CXI_PEER_DOWN) &&
             (peer->state != UCT_CXI_PEER_CREQ_SENT))) {
            ucs_debug("cxi ignoring unexpected CREP from initiator 0x%x",
                      process);
            return;
        }
        if (UCT_CXI_CTRL_ECHO(mb) != iface->fc.epoch) {
            ucs_debug("cxi ignoring CREP answering another incarnation");
            return;
        }
        peer->remote_epoch = UCT_CXI_CTRL_EPOCH24(mb);

        /* The grant is the whole window: nothing has been spent yet. The
         * granule of the counters its piggybacks carry follows from it, as it
         * did for the peer when it sent it. */
        memset(&peer->tx, 0, sizeof(peer->tx));
        peer->tx.avail_slots = UCT_CXI_CREP_SLOTS(hd);
        peer->pb_shift[0]    = uct_cxi_fc_pb_shift(UCT_CXI_CREP_SLOTS(hd),
                                                   UCT_CXI_FC_PB_SLOT_BITS);
        for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
            peer->tx.avail_units[cls] = UCT_CXI_CREP_UNITS(hd, cls);
            peer->pb_shift[1 + cls]   = uct_cxi_fc_pb_shift(
                    UCT_CXI_CREP_UNITS(hd, cls), UCT_CXI_FC_PB_UNIT_BITS);
        }

        uct_cxi_peer_connected(iface, peer, UCT_CXI_PEER_UP);
        ucs_debug("cxi peer nid 0x%x pid %u is up: %d slots, %d AM units, "
                  "%d tag units", uct_cxi_peer_nid(iface, peer),
                  uct_cxi_peer_pid(iface, peer), peer->tx.avail_slots,
                  peer->tx.avail_units[UCT_CXI_FC_AM],
                  peer->tx.avail_units[UCT_CXI_FC_TAG]);
        break;

    case UCT_CXI_CTRL_GRANT:
        peer = uct_cxi_peer_lookup(iface, process);
        if ((peer == NULL) || (peer->state != UCT_CXI_PEER_UP) ||
            (UCT_CXI_CTRL_EPOCH24(mb) != peer->remote_epoch)) {
            ucs_debug("cxi ignoring GRANT from initiator 0x%x", process);
            return;
        }
        units[UCT_CXI_FC_AM]  = (uint32_t)hd;
        units[UCT_CXI_FC_TAG] = UCT_CXI_CTRL_ECHO(mb);
        uct_cxi_fc_apply_grant(iface, peer, (uint32_t)(hd >> 32), units, 32, 32,
                               NULL);
        break;

    default:
        ucs_debug("cxi ignoring control message of unknown type %u",
                  UCT_CXI_CTRL_TYPE(mb));
        break;
    }
}


/* -------------------------------------------------------------------------
 * Handshake driver
 * -------------------------------------------------------------------------
 */

/*
 * Send \a conn's peer a CREQ and arm the timer for the next one (or for the
 * deadline). A CREQ that could not go out (no control slot, command queue
 * full) is tried again after the shortest delay, and does not count as an
 * attempt.
 */
static void uct_cxi_peer_conn_attempt(uct_cxi_peer_conn_t *conn)
{
    uct_cxi_iface_t *iface = conn->iface;
    uct_cxi_peer_t  *peer  = conn->peer;
    ucs_time_t       delay;
    unsigned         shift;

    if (uct_cxi_ctrl_send(iface, peer, UCT_CXI_CTRL_CREQ,
                          UCT_CXI_CTRL_MATCH(UCT_CXI_CTRL_CREQ,
                                             iface->fc.epoch, 0),
                          iface->fc.epoch, 0, NULL) != UCS_OK) {
        delay = 0;
    } else {
        peer->state = UCT_CXI_PEER_CREQ_SENT;
        shift       = ucs_min(conn->attempts, 10u);
        delay       = ucs_time_from_usec(
                              ucs_min((uint64_t)UCT_CXI_CTRL_RETRY_BASE_US
                                              << shift,
                                      (uint64_t)UCT_CXI_CTRL_RETRY_MAX_US));
        conn->attempts++;
    }

    uct_cxi_fc_timer_add(iface, &conn->timer, delay);
}

/* The timer of a handshake: give up if its time is up, else resend. */
static void uct_cxi_peer_conn_timer(ucs_wtimer_t *timer)
{
    uct_cxi_peer_conn_t *conn  = ucs_container_of(timer, uct_cxi_peer_conn_t,
                                                  timer);
    uct_cxi_iface_t     *iface = conn->iface;
    uct_cxi_peer_t      *peer  = conn->peer;

    if (ucs_get_time() > conn->deadline) {
        ucs_warn("cxi handshake with nid 0x%x pid %u timed out after %u "
                 "attempts", uct_cxi_peer_nid(iface, peer),
                 uct_cxi_peer_pid(iface, peer), conn->attempts);
        uct_cxi_peer_connected(iface, peer, UCT_CXI_PEER_FAILED); /* frees conn */
        return;
    }

    uct_cxi_peer_conn_attempt(conn);
}

void uct_cxi_peer_connect(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    uct_cxi_peer_conn_t *conn;
    ucs_time_t           now = ucs_get_time();

    if ((peer->state != UCT_CXI_PEER_DOWN) || (peer->conn != NULL)) {
        return;
    }

    conn = ucs_mpool_get(&iface->fc.conn_pool);
    if (conn == NULL) {
        ucs_error("cxi no memory to connect to a peer, giving up on it");
        uct_cxi_peer_connected(iface, peer, UCT_CXI_PEER_FAILED);
        return;
    }

    ucs_wtimer_init(&conn->timer, uct_cxi_peer_conn_timer);
    conn->iface    = iface;
    conn->peer     = peer;
    conn->deadline = now + iface->fc.connect_timeout;
    conn->attempts = 0;
    peer->conn     = conn;

    iface->fc.num_connecting++;
    uct_cxi_peer_conn_attempt(conn);
}

/* Is \a peer owed any credits we have not put on the wire? */
static int uct_cxi_fc_owed(const uct_cxi_peer_t *peer)
{
    unsigned cls;

    if (peer->rx.ret_slots != peer->rx.adv_slots) {
        return 1;
    }
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        if (peer->rx.ret_units[cls] != peer->rx.adv_units[cls]) {
            return 1;
        }
    }
    return 0;
}

/*
 * uct_cxi_fc_send_grant -- tell \a peer how much of its traffic we have
 * processed, cumulatively. UCS_ERR_NO_RESOURCE (no control slot, command queue
 * full) leaves it queued to try again from progress.
 */
static ucs_status_t uct_cxi_fc_send_grant(uct_cxi_iface_t *iface,
                                          uct_cxi_peer_t *peer)
{
    uint32_t     slots = peer->rx.ret_slots;
    uint32_t     units[UCT_CXI_FC_NUM_CLASSES];
    ucs_status_t status;
    unsigned     cls;

    memcpy(units, peer->rx.ret_units, sizeof(units));

    status = uct_cxi_ctrl_send(
            iface, peer, UCT_CXI_CTRL_GRANT,
            UCT_CXI_CTRL_MATCH(UCT_CXI_CTRL_GRANT, iface->fc.epoch,
                               units[UCT_CXI_FC_TAG]),
            ((uint64_t)slots << 32) | units[UCT_CXI_FC_AM], slots, units);
    if (status == UCS_OK) {
        peer->rx.adv_slots = slots;
        for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
            peer->rx.adv_units[cls] = units[cls];
        }
    }
    return status;
}

/* Put \a peer on the list of those waiting for a GRANT, and make sure the
 * timer that retries the list is running. */
static void uct_cxi_fc_queue_grant(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    unsigned shift;

    if (ucs_list_is_empty(&peer->grants)) {
        ucs_list_add_tail(&iface->fc.grants, &peer->grants);
    }

    shift = ucs_min(iface->fc.grant_failures, 10u);
    uct_cxi_fc_timer_add(iface, &iface->fc.grant_timer,
                         ucs_time_from_usec(
                                 ucs_min((uint64_t)UCT_CXI_CTRL_RETRY_BASE_US
                                                 << shift,
                                         (uint64_t)UCT_CXI_CTRL_RETRY_MAX_US)));
}

void uct_cxi_fc_grant_wanted(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    if (!ucs_list_is_empty(&peer->grants)) {
        return; /* already waiting */
    }

    if (uct_cxi_fc_send_grant(iface, peer) != UCS_OK) {
        uct_cxi_fc_queue_grant(iface, peer);
    }
}

/*
 * Send the GRANTs that are waiting, oldest first, until one cannot be sent
 * (the TX queue is full: the others could not be either). Called when TX
 * completions have made room, before the sends waiting in pending queues get
 * it, and from the timer in case no completion comes.
 */
void uct_cxi_fc_flush_grants(uct_cxi_iface_t *iface)
{
    uct_cxi_peer_t *peer;

    while (!ucs_list_is_empty(&iface->fc.grants)) {
        peer = ucs_list_head(&iface->fc.grants, uct_cxi_peer_t, grants);

        /* Still owed anything? A piggyback may have carried it meanwhile. */
        if (uct_cxi_fc_owed(peer) &&
            (uct_cxi_fc_send_grant(iface, peer) != UCS_OK)) {
            return;
        }

        ucs_list_del(&peer->grants);
        ucs_list_head_init(&peer->grants);
    }
}

static void uct_cxi_fc_grant_timer(ucs_wtimer_t *timer)
{
    uct_cxi_iface_t *iface = ucs_container_of(timer, uct_cxi_iface_t,
                                              fc.grant_timer);

    uct_cxi_fc_flush_grants(iface);
    if (!ucs_list_is_empty(&iface->fc.grants)) {
        /* Still waiting: again, a little later. */
        uct_cxi_fc_queue_grant(iface, ucs_list_head(&iface->fc.grants,
                                                    uct_cxi_peer_t, grants));
    }
}

#endif /* UCT_CXI_DISABLE_FC */
