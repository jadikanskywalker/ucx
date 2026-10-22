/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI endpoint definitions.
 */

#ifndef UCT_CXI_EP_H
#define UCT_CXI_EP_H

#include "cxi_iface.h"

#include <uct/base/uct_iface.h>
#include <uct/api/uct.h>
#include <ucs/datastruct/arbiter.h>
#include <ucs/time/time.h>

#include <cxi_prov_hw.h>

/*
 * Per-endpoint adaptive backoff, applied after observing a
 * C_RC_PT_DISABLED-class TX completion on this EP's own sends.
 *
 * Two independent controls, both needed (see uct_cxi_ep_tx_complete):
 *   - max_outstanding bounds *concurrency* — how many ops this EP may have
 *     in flight. Halved (floor 1) on failure, doubled back toward
 *     unconstrained after a healthy streak.
 *   - retry_backoff_until bounds *cadence* — how soon this EP may submit
 *     (or have a queued pending request retried) again after a failure.
 *     Exponential per consecutive failure, capped, reset on success.
 * A fixed concurrency cap alone doesn't slow *how fast* a freed slot gets
 * reused (the arbiter can redrive a queued retry on the very next
 * progress() call, microseconds later) — that's what previously caused
 * sub-100us retry bursts tripping the PTE flap limit under load.
 */
#define UCT_CXI_FC_BACKOFF_BASE_US        100      /* first-failure backoff */
#define UCT_CXI_FC_BACKOFF_MAX_US         100000   /* 100ms cap */
#define UCT_CXI_FC_HEALTHY_STREAK         8        /* consecutive OK completions
                                                        before growing back */
#define UCT_CXI_EP_MAX_OUTSTANDING_UNLIMITED UINT_MAX


/**
 * Per-send-op tracking record.
 *
 * Allocated from iface->tx.op_pool for zcopy/short ops, or embedded as the
 * first field of uct_cxi_send_desc_t for bcopy ops.  Stored via user_ptr so
 * that iface_progress can retrieve it on C_EVENT_ACK or C_EVENT_REPLY.
 *
 * handler: NULL for zcopy/short (default path: invoke comp, mpool_put op).
 *          Set for bcopy: handler owns completion + returns desc to pool.
 *          Receives the real completion status — must skip any data
 *          copy/unpack (unpack_cb, memcpy) unless status == UCS_OK, since
 *          a failed GET/fetch's "result" buffer was never actually written
 *          by the remote and must not be delivered to the caller.
 */
typedef struct uct_cxi_send_op {
    struct uct_cxi_ep *ep;      /**< Owning EP — used to decrement outstanding */
    uct_completion_t  *comp;    /**< Caller completion callback, or NULL       */
    void (*handler)(struct uct_cxi_send_op *, ucs_status_t); /**< NULL = default zcopy path */
#ifndef UCT_CXI_DISABLE_FC
    uint32_t           fc_units;    /**< flow-control cost of buffer space, in
                                         units, of class fc_class...          */
    uint8_t            fc_slots;    /**< ...and in event slots, to take back if
                                         the send fails or is answered from the
                                         priority list; 0 if it was not
                                         charged. Must be 0 whenever the op is
                                         not in use: set when the pool creates
                                         it, cleared by the completion that
                                         consumed it                          */
    uint8_t            fc_class;    /**< uct_cxi_fc_class_t of the charge   */
#endif
} uct_cxi_send_op_t;


/**
 * Bounce-buffer descriptor for put_bcopy / get_bcopy.
 *
 * op must be first so that (uct_cxi_send_op_t *)desc == &desc->op; the NIC
 * stores desc as user_ptr and iface_progress casts it back to send_op_t.
 *
 * iova and lac are pre-computed at pool initialisation time (obj_init
 * callback) from the chunk's cxil_map registration — zero per-op overhead.
 *
 * The data payload immediately follows the struct: (uint8_t *)(desc + 1).
 * Its size is iface->tx.max_bcopy.
 */
typedef struct uct_cxi_send_desc {
    uct_cxi_send_op_t       op;         /**< Must be first                          */
    uct_unpack_callback_t   unpack_cb;  /**< get_bcopy: deliver data to caller      */
    void                   *unpack_arg; /**< get_bcopy: arg passed to unpack_cb     */
    size_t                  length;     /**< get_bcopy: byte count for unpack_cb    */
    uint64_t                iova;       /**< Pre-computed IOVA of data area (desc+1)*/
    uint8_t                 lac;        /**< LAC of the cxil_map covering this chunk*/
} uct_cxi_send_desc_t;


/**
 * CXI endpoint.
 *
 * rem_nid and rem_pid identify the remote peer.  All DFAs are built eagerly
 * at ep_create — no hot-path conditional needed.
 *
 * dfa_rma[lac]: per-LAC DFA for restricted-mode RMA/AMO (pid_offset = lac).
 *   All UCT_CXI_MAX_LACS entries are built at ep_create; an operation
 *   selects dfa_rma[rkey->lac] -- the *target* buffer's LAC, since that's
 *   what determines which of the target's per-LAC PTEs/LEs must resolve
 *   remote_offset (see cxi_rma.c for why routing has to be per-LAC).
 * dfa_am: DFA for unrestricted Active Messages (pid_offset = UCT_CXI_PTE_AM).
 */
typedef struct uct_cxi_ep {
    uct_base_ep_t     super;                              /**< Must be first */
    uint32_t          rem_nid;                            /**< Remote NID */
    uint32_t          rem_pid;                            /**< Remote PID */
    union c_fab_addr  dfa_rma[UCT_CXI_MAX_LACS];         /**< Per-LAC DFAs (pid_offset=lac) */
    uint8_t           dfa_rma_idx_ext[UCT_CXI_MAX_LACS]; /**< Per-LAC idx_ext */
    union c_fab_addr  dfa_am;                             /**< AM DFA (pid_offset=UCT_CXI_PTE_AM) */
    uint8_t           dfa_am_idx_ext;                    /**< AM idx_ext */
    union c_fab_addr  dfa_tag;                            /**< TAG DFA (pid_offset=UCT_CXI_PTE_TAG) */
    uint8_t           dfa_tag_idx_ext;                   /**< TAG idx_ext */
    unsigned          outstanding;     /**< In-flight send ops for this EP */
    uct_completion_t *flush_comp;     /**< Pending flush completion, or NULL */
    ucs_arbiter_group_t arb_group;     /**< Pending-request queue for this EP */
    unsigned          max_outstanding; /**< Adaptive concurrency cap — new sends
                                             on this EP return UCS_ERR_NO_RESOURCE
                                             once outstanding reaches this.
                                             UCT_CXI_EP_MAX_OUTSTANDING_UNLIMITED
                                             = unconstrained (default). */
    ucs_time_t        retry_backoff_until; /**< Adaptive retry cadence — new
                                             sends *and* already-queued pending
                                             retries on this EP are held back
                                             until this deadline. 0 = no
                                             backoff in effect. */
    unsigned          consecutive_failures;  /**< For backoff/shrink growth */
    unsigned          consecutive_successes; /**< For backoff/grow reset    */
#ifndef UCT_CXI_DISABLE_FC
    struct uct_cxi_peer *peer;         /**< Remote iface's flow-control state,
                                             shared with every ep to it; NULL
                                             when flow control is off */
    struct uct_cxi_ep *next_blocked;   /**< Next ep waiting for credits on the
                                             same peer (uct_cxi_peer_t::blocked) */
    uint8_t           fc_listed;       /**< Is on peer->blocked */
#endif
    uint8_t           destroyed;       /**< uct_ep_destroy() was called while
                                             sends were still in flight; the
                                             last completion frees the ep (see
                                             uct_cxi_ep_destroy) */
    uint8_t           rndv_hdr_announced; /**< 0 until this ep's one-time
                                             rendezvous-header announce
                                             (ep_id, md_index) has been sent
                                             -- see uct_ep_tag_rndv_zcopy and
                                             uct_cxi_ep_send_rndv_hdr_announce
                                             in cxi_am.c. Not resent once
                                             sent (only reset to 0 when the
                                             send is refused, so the next
                                             rndv send retries). */
} uct_cxi_ep_t;

/*
 * uct_cxi_ep_tx_complete_slow — update this EP's adaptive backoff state after
 * a TX completion that changes it (see uct_cxi_ep_tx_complete() below).
 * Defined in cxi_ep.c.
 */
void uct_cxi_ep_tx_complete_slow(uct_cxi_ep_t *ep, ucs_status_t status);

/*
 * uct_cxi_ep_tx_complete — the usual completion (success, on an ep whose
 * concurrency cap has never been cut, or has grown back to unconstrained) has
 * nothing to update: the cap cannot grow further, and a streak of successes
 * only matters to an ep that has failed. Everything else is for
 * uct_cxi_ep_tx_complete_slow().
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_ep_tx_complete(uct_cxi_ep_t *ep, ucs_status_t status)
{
    if (ucs_unlikely((status != UCS_OK) ||
                     (ep->max_outstanding !=
                      UCT_CXI_EP_MAX_OUTSTANDING_UNLIMITED))) {
        uct_cxi_ep_tx_complete_slow(ep, status);
    }
}


/*
 * uct_cxi_ep_fc_blocked — true if this send should be deferred to the
 * pending/arbiter retry path rather than attempted now.
 *
 * Four independent reasons, all gate identically (return
 * UCS_ERR_NO_RESOURCE, same as ordinary pool exhaustion — no new
 * caller-visible status):
 *   - pte_fc->exhausted: the *specific* PTE this op targets has hit
 *     matching-resource exhaustion (AM only — pass NULL for RMA/AMO ops,
 *     which never populate this; see uct_cxi_pte_fc_t). Unrelated PTEs'
 *     traffic is unaffected.
 *   - iface->tx.outstanding >= iface->tx.max_inflight: the TX event queue
 *     has no slot left for another completion. Every counted send yields
 *     exactly one TX event, so this is what keeps the queue from
 *     overflowing: a send takes a slot when it is rung and gives it back
 *     when its completion is processed (RC's tx_cq_available, per iface).
 *   - ep->outstanding >= ep->max_outstanding: this EP's adaptive
 *     concurrency cap (see uct_cxi_ep_tx_complete).
 *   - ep->retry_backoff_until: this EP's adaptive retry-cadence backoff,
 *     set after a C_RC_PT_DISABLED-class completion. Zero (the usual) is
 *     tested first so that the clock is only read while a backoff is set.
 *
 * Deliberately not gated on the RX EQ being drained after a drop: with
 * separate TX and RX event queues, local sends only produce TX completions
 * and can no longer refill the RX queue out from under that drain.
 */
static UCS_F_ALWAYS_INLINE int
uct_cxi_ep_fc_blocked(uct_cxi_ep_t *ep, const uct_cxi_iface_t *iface,
                      const uct_cxi_pte_fc_t *pte_fc)
{
    return ucs_unlikely(((pte_fc != NULL) && pte_fc->exhausted) ||
                         (iface->tx.outstanding >= iface->tx.max_inflight) ||
                         (ep->outstanding >= ep->max_outstanding) ||
                         ((ep->retry_backoff_until != 0) &&
                          (ep->retry_backoff_until > ucs_get_time())));
}

/*
 * IDC "short" sends (AM, tag, rendezvous-header announce) carry no per-send
 * descriptor, so their completion is tracked by tagging the command's user_ptr
 * with UCT_CXI_USER_PTR_SHORT and storing the ep pointer itself: no pool
 * element to take or return, and the completion handler gets the ep it needs
 * to account the send against. Ops, which are pointers to a uct_cxi_send_op_t
 * (at least 8-byte aligned), never have this bit set.
 *
 * The top byte of a short's user_ptr carries its flow-control cost, so a
 * failed one can be refunded without a descriptor to look it up in: bits
 * [62:56] the cost in units (a short is at most 192 bytes, 3 units), bit 63
 * set if it was charged at all. Userspace pointers have those bits clear. The
 * class it was charged to is bit 2, set for tag matching (an endpoint is at
 * least 8-byte aligned); its event slots are those of the class's short
 * message: one, for an Active Message or an eager tag message.
 *
 * Tracked shorts exist to make connected-endpoint flow control possible --
 * without a completion there is nothing to refund a lost send's credit
 * from -- so a build without it keeps the untracked fire-and-forget path.
 */
#define UCT_CXI_USER_PTR_SHORT  1ULL

/* A user_ptr that is a pointer to a control request (cxi_fc.h), not an op or
 * an ep. */
#define UCT_CXI_USER_PTR_CTRL   2ULL

/* Set in the user_ptr of a tracked short charged to the tag class. */
#define UCT_CXI_USER_PTR_TAG    4ULL

#define UCT_CXI_USER_PTR_UNITS_SHIFT    56
#define UCT_CXI_USER_PTR_UNITS_MASK     0x7fULL
#define UCT_CXI_USER_PTR_CREDITED       (1ULL << 63)
#define UCT_CXI_USER_PTR_PTR_MASK       ((1ULL << UCT_CXI_USER_PTR_UNITS_SHIFT) - 1)

#ifdef UCT_CXI_DISABLE_FC

static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_cstate(struct c_cstate_cmd *cstate, uct_cxi_iface_t *iface)
{
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_hdr(struct c_idc_msg_hdr *hdr, uct_cxi_ep_t *ep,
                      unsigned cls, unsigned units, int credited)
{
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_commit(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
}

/* Flow control compiled out: nothing is charged, nothing piggybacked. */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_fc_reserve(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, unsigned cls,
                   unsigned slots, unsigned units, int *credited_p)
{
    *credited_p = 0;
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_debit(uct_cxi_ep_t *ep, int credited, unsigned cls, unsigned slots,
                 unsigned units)
{
}

static UCS_F_ALWAYS_INLINE uint64_t
uct_cxi_fc_pb_bits(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
    return 0;
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_pb_sent(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, uint64_t bits)
{
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_op_fc_set(uct_cxi_send_op_t *op, int credited, unsigned cls,
                  unsigned slots, unsigned units)
{
}

#else

/**
 * Make the send's completion event land on the TX EQ. Goes in the c_state
 * command that precedes the IDC message.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_cstate(struct c_cstate_cmd *cstate, uct_cxi_iface_t *iface)
{
    cstate->eq = iface->tx_eq.evtq->eqn;
}

/**
 * Tag the completion with \a ep and the send's flow-control cost. For an
 * unrestricted IDC message the event's user_ptr is the one in the message's
 * own header -- the c_state command's user_ptr only applies to restricted IDC
 * puts -- so this goes in the c_idc_msg_hdr, not the c_state.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_hdr(struct c_idc_msg_hdr *hdr, uct_cxi_ep_t *ep,
                      unsigned cls, unsigned units, int credited)
{
    ucs_assert(((uintptr_t)ep & (UCT_CXI_USER_PTR_SHORT |
                                 UCT_CXI_USER_PTR_CTRL |
                                 UCT_CXI_USER_PTR_TAG)) == 0);
    ucs_assert(((uint64_t)(uintptr_t)ep & ~UCT_CXI_USER_PTR_PTR_MASK) == 0);
    ucs_assert(units <= UCT_CXI_USER_PTR_UNITS_MASK);
    hdr->user_ptr = (uint64_t)(uintptr_t)ep | UCT_CXI_USER_PTR_SHORT |
                    ((cls == UCT_CXI_FC_TAG) ? UCT_CXI_USER_PTR_TAG : 0) |
                    ((uint64_t)units << UCT_CXI_USER_PTR_UNITS_SHIFT) |
                    (credited ? UCT_CXI_USER_PTR_CREDITED : 0);
}

/** Account the send once it has been rung (undone by its completion). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_commit(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
    ep->outstanding++;
    iface->tx.outstanding++;
}

/** Slow path of uct_cxi_fc_reserve(): the peer is not (yet) up. */
BEGIN_C_DECLS
ucs_status_t uct_cxi_fc_reserve_slow(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                                     int *credited_p);
END_C_DECLS

/**
 * May a send of class \a cls costing \a slots event slots and \a units of
 * that class's buffer space go out to this ep's peer? If so, \a *credited_p
 * says whether it must be charged (the peer is credit-controlled) or not (no
 * flow control: the peer is LEGACY, or the ep has no peer record). If not,
 * UCS_ERR_NO_RESOURCE: no credits of either kind, or the handshake is still
 * in flight; iface->tx.credit_block is set so the pending queue knows to wait
 * for credits rather than for interface resources.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_fc_reserve(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, unsigned cls,
                   unsigned slots, unsigned units, int *credited_p)
{
    uct_cxi_peer_t *peer = ep->peer;

    if (ucs_likely((peer != NULL) && (peer->state == UCT_CXI_PEER_UP))) {
        if (ucs_likely((peer->tx.avail_slots >= (int32_t)slots) &&
                       (peer->tx.avail_units[cls] >= (int32_t)units))) {
            *credited_p = 1;
            return UCS_OK;
        }
        iface->tx.credit_block = 1;
        return UCS_ERR_NO_RESOURCE;
    }

    return uct_cxi_fc_reserve_slow(ep, iface, credited_p);
}

/** Charge a send that has been rung, if \a credited. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_debit(uct_cxi_ep_t *ep, int credited, unsigned cls, unsigned slots,
                 unsigned units)
{
    uct_cxi_peer_t *peer = ep->peer;

    if (credited) {
        peer->tx.avail_slots       -= (int32_t)slots;
        peer->tx.avail_units[cls]  -= (int32_t)units;
        peer->tx.used_slots        += slots;
        peer->tx.used_units[cls]   += units;
    }
}

/**
 * match_bits to piggyback on an outgoing Active Message to this ep's peer:
 * the credits we owe it for messages it sent us and we have processed, or 0
 * if nothing is owed. The counters go in granules (see uct_cxi_fc_pb_shift),
 * so a piggyback is only worth sending once a counter has moved on by at least
 * one. See uct_cxi_fc_pb_sent() for the other half.
 */
static UCS_F_ALWAYS_INLINE uint64_t
uct_cxi_fc_pb_bits(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
    uct_cxi_peer_t     *peer  = ep->peer;
    const uint8_t      *shift = iface->fc.pb_shift;
    uint64_t            bits;
    unsigned            cls;
    int                 owed;

    if (ucs_likely(peer == NULL)) {
        return 0;
    }

    owed = ((peer->rx.ret_slots >> shift[0]) !=
            (peer->rx.adv_slots >> shift[0]));
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        owed |= ((peer->rx.ret_units[cls] >> shift[1 + cls]) !=
                 (peer->rx.adv_units[cls] >> shift[1 + cls]));
    }
    if (ucs_likely(!owed)) {
        return 0;
    }

    bits = UCT_CXI_FC_PB_VALID |
           ((uint64_t)((peer->rx.ret_slots >> shift[0]) &
                       UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_SLOT_BITS))
                   << UCT_CXI_FC_PB_SLOT_SHIFT) |
           ((uint64_t)(iface->fc.epoch &
                       UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_EPOCH_BITS))
                   << UCT_CXI_FC_PB_EPOCH_SHIFT);
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        bits |= (uint64_t)((peer->rx.ret_units[cls] >> shift[1 + cls]) &
                           UCT_CXI_FC_PB_MASK(UCT_CXI_FC_PB_UNIT_BITS))
                << UCT_CXI_FC_PB_UNIT_SHIFT(cls);
    }
    return bits;
}

/** Advance \a *adv to \a ret rounded down to a granule, never back. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_pb_advance(uint32_t *adv, uint32_t ret, unsigned shift)
{
    uint32_t rounded = (ret >> shift) << shift;

    if ((int32_t)(rounded - *adv) > 0) {
        *adv = rounded;
    }
}

/**
 * The message carrying \a bits (from uct_cxi_fc_pb_bits) has been rung: the
 * peer now knows our counters to the granule, no further than that. (A GRANT
 * may have told it more exactly: that stays.)
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_pb_sent(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, uint64_t bits)
{
    uct_cxi_peer_t *peer  = ep->peer;
    const uint8_t  *shift = iface->fc.pb_shift;
    unsigned        cls;

    if (bits != 0) {
        uct_cxi_fc_pb_advance(&peer->rx.adv_slots, peer->rx.ret_slots,
                              shift[0]);
        for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
            uct_cxi_fc_pb_advance(&peer->rx.adv_units[cls],
                                  peer->rx.ret_units[cls], shift[1 + cls]);
        }
    }
}

/** Record a pooled op's flow-control charge, to refund if it fails. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_op_fc_set(uct_cxi_send_op_t *op, int credited, unsigned cls,
                  unsigned slots, unsigned units)
{
    op->fc_slots = credited ? (uint8_t)slots : 0;
    op->fc_class = (uint8_t)cls;
    op->fc_units = units;
}

#endif /* UCT_CXI_DISABLE_FC */

/**
 * Send \a length bytes of \a data as one unrestricted inline (IDC) message to
 * \a dfa: a c_state command that says where the send's completion goes, then
 * the message itself, rung together, with the send counted against its ep and
 * tracked by its completion (see uct_cxi_idc_track_hdr; \a cls, \a units and
 * \a credited are its flow-control charge, which the caller applies).
 *
 * UCS_ERR_NO_RESOURCE if the command queue has no room, with nothing counted.
 * A c_state already written then stays in the queue, harmlessly: every IDC
 * send writes its own before its message. \a what names the caller in the
 * log if the failure is not a full queue.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_ep_idc_send(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                    union c_fab_addr dfa, uint8_t idx_ext, uint64_t match_bits,
                    const void *data, size_t length, unsigned cls,
                    unsigned units, int credited, const char *what)
{
    struct c_cstate_cmd  cstate = {};
    struct c_idc_msg_hdr hdr    = {};
    int                  ret;

    cstate.event_send_disable = 1;
    cstate.restricted         = 0;
    cstate.initiator          = iface->match_id;
    cstate.index_ext          = idx_ext;
    uct_cxi_idc_track_cstate(&cstate, iface);

    ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, what, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    hdr.dfa        = dfa;
    hdr.match_bits = match_bits;
    uct_cxi_idc_track_hdr(&hdr, ep, cls, units, credited);

    ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &hdr, data, length);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, what, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    uct_cxi_idc_track_commit(ep, iface);
    return UCS_OK;
}

ucs_status_t uct_cxi_ep_create(const uct_ep_params_t *params, uct_ep_h *ep_p);
void         uct_cxi_ep_destroy(uct_ep_h tl_ep);

ucs_status_t uct_cxi_ep_flush(uct_ep_h tl_ep, unsigned flags,
                               uct_completion_t *comp);
ucs_status_t uct_cxi_ep_fence(uct_ep_h tl_ep, unsigned flags);

ucs_status_t uct_cxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                     unsigned flags);
void uct_cxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                               void *arg);

/* Arbiter dispatch callback — called from uct_cxi_iface_progress() via
 * ucs_arbiter_dispatch() to drain queued pending requests. */
ucs_arbiter_cb_result_t
uct_cxi_ep_process_pending(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                            ucs_arbiter_elem_t *elem, void *arg);

#endif /* UCT_CXI_EP_H */
