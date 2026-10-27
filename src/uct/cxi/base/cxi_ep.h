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

#include <cxi_prov_hw.h>

/**
 * Per-send tracking record, the user_ptr of its ACK/REPLY. From
 * iface->tx.op_pool, or the first field of a uct_cxi_send_desc_t for bcopy.
 *
 * handler: NULL for zcopy (invoke comp, free op). Set for bcopy: it completes
 * and frees the desc, and must not unpack data unless status == UCS_OK.
 */
typedef struct uct_cxi_send_op uct_cxi_send_op_t;

typedef void (*uct_cxi_send_op_func_t)(uct_cxi_send_op_t *op,
                                       ucs_status_t status);

struct uct_cxi_send_op {
    /* Owning EP, to decrement outstanding */
    struct uct_cxi_ep      *ep;
    /* Caller completion, or NULL */
    uct_completion_t       *comp;
    /* NULL = default zcopy path */
    uct_cxi_send_op_func_t handler;
#ifndef UCT_CXI_DISABLE_FC
    /* Flow-control cost of buffer space, in units, of class fc_class... */
    uint32_t fc_units;
    /* ...and in event slots, to take back on failure or a priority match; 0 if
     * uncharged. Must be 0 when the op is unused. */
    uint8_t fc_slots;
    /* uct_cxi_fc_class_t of the charge */
    uint8_t fc_class;
#endif
};


/**
 * Bounce-buffer descriptor for put_bcopy / get_bcopy. \a op must be first
 * (desc is the user_ptr). iova and lac are set at pool init. The payload
 * follows the struct, iface->tx.max_bcopy bytes.
 */
typedef struct uct_cxi_send_desc {
    /* Must be first */
    uct_cxi_send_op_t     op;
    /* get_bcopy: deliver data to the caller, with its arg and byte count */
    uct_unpack_callback_t unpack_cb;
    void                  *unpack_arg;
    size_t                length;
    /* Pre-computed IOVA of the data area (desc + 1) */
    uint64_t              iova;
    /* LAC of the cxil_map covering this chunk */
    uint8_t               lac;
} uct_cxi_send_desc_t;


/**
 * CXI endpoint. All DFAs are built at ep_create.
 *
 * dfa_rma[lac]: restricted RMA/AMO DFA; an operation uses the entry of the
 *   target buffer's LAC (rkey->lac), which selects the target PTE.
 */
typedef struct uct_cxi_ep {
    /* Must be first */
    uct_base_ep_t       super;
    uint32_t            rem_nid;
    uint32_t            rem_pid;
    /* Per-LAC DFAs (pid_offset=lac) and their idx_ext */
    union c_fab_addr    dfa_rma[UCT_CXI_MAX_LACS];
    uint8_t             dfa_rma_idx_ext[UCT_CXI_MAX_LACS];
    /* AM DFA (pid_offset=UCT_CXI_PTE_AM) and its idx_ext */
    union c_fab_addr    dfa_am;
    uint8_t             dfa_am_idx_ext;
    /* TAG DFA (pid_offset=UCT_CXI_PTE_TAG) and its idx_ext */
    union c_fab_addr    dfa_tag;
    uint8_t             dfa_tag_idx_ext;
    /* In-flight send ops for this EP */
    unsigned            outstanding;
    /* Pending flush completion, or NULL */
    uct_completion_t    *flush_comp;
    /* Pending-request queue for this EP */
    ucs_arbiter_group_t arb_group;
#ifndef UCT_CXI_DISABLE_FC
    /* Remote iface's flow-control state, shared by its eps; NULL if off */
    struct uct_cxi_peer *peer;
    /* Next ep waiting for credits on the same peer (uct_cxi_peer_t::blocked) */
    struct uct_cxi_ep *next_blocked;
    /* Is on peer->blocked */
    uint8_t fc_listed;
#endif
    /* Destroyed with sends in flight; the last completion frees it */
    uint8_t destroyed;
    /* The one-time rendezvous-header announce has been sent */
    uint8_t rndv_hdr_announced;
} uct_cxi_ep_t;

static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *uct_cxi_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_send_op_set(uct_cxi_send_op_t *op, uct_cxi_ep_t *ep,
                    uct_completion_t *comp, uct_cxi_send_op_func_t handler)
{
    op->ep      = ep;
    op->comp    = comp;
    op->handler = handler;
}

/* Account a send that has been rung (undone by its completion). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_ep_tx_commit(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
    ep->outstanding++;
    iface->tx.outstanding++;
}

/*
 * True if a send must wait on the pending queue (UCS_ERR_NO_RESOURCE):
 *   - the target PTE hit matching-resource exhaustion (\a pte_fc, NULL for
 *     RMA/AMO);
 *   - the TX queue has no slot for another completion: each counted send
 *     yields one event, so tx.max_inflight keeps the queue from overflowing.
 */
static UCS_F_ALWAYS_INLINE int
uct_cxi_iface_tx_blocked(const uct_cxi_iface_t *iface,
                         const uct_cxi_pte_fc_t *pte_fc)
{
    return ucs_unlikely(((pte_fc != NULL) && pte_fc->exhausted) ||
                        (iface->tx.outstanding >= iface->tx.max_inflight));
}

/*
 * A short (IDC) send has no descriptor: its user_ptr is the ep pointer tagged
 * with UCT_CXI_USER_PTR_SHORT (ops are aligned pointers and never have the
 * bit). Bits [62:56] carry its flow-control cost in units, bit 63 whether it
 * was charged, and bit 2 (UCT_CXI_USER_PTR_TAG) the class (set for tag
 * matching), so a failed send can be refunded.
 *
 * Active Message shorts are tracked only with flow control (no refund
 * otherwise); restricted shorts (RMA, atomics) always, for the flush.
 */
#define UCT_CXI_USER_PTR_SHORT 1ULL

/* Set in the user_ptr of a tracked short charged to the tag class. */
#define UCT_CXI_USER_PTR_TAG 4ULL

#define UCT_CXI_USER_PTR_UNITS_SHIFT 56
#define UCT_CXI_USER_PTR_UNITS_MASK  0x7fULL
#define UCT_CXI_USER_PTR_CREDITED    (1ULL << 63)

#define UCT_CXI_USER_PTR_PTR_MASK ((1ULL << UCT_CXI_USER_PTR_UNITS_SHIFT) - 1)

/* The user_ptr of an uncharged short (put_short, atomic post). */
static UCS_F_ALWAYS_INLINE uint64_t
uct_cxi_ep_short_user_ptr(const uct_cxi_ep_t *ep)
{
    ucs_assert(((uintptr_t)ep &
                (UCT_CXI_USER_PTR_SHORT | UCT_CXI_USER_PTR_TAG)) == 0);
    ucs_assert(((uintptr_t)ep & ~UCT_CXI_USER_PTR_PTR_MASK) == 0);
    return (uint64_t)(uintptr_t)ep | UCT_CXI_USER_PTR_SHORT;
}

#ifdef UCT_CXI_DISABLE_FC

static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_cstate(struct c_cstate_cmd *cstate, uct_cxi_iface_t *iface)
{
}

static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_hdr(struct c_idc_msg_hdr *hdr, uct_cxi_ep_t *ep, unsigned cls,
                      unsigned units, int credited)
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

static UCS_F_ALWAYS_INLINE void uct_cxi_fc_debit(uct_cxi_ep_t *ep, int credited,
                                                 unsigned cls, unsigned slots,
                                                 unsigned units)
{
}

static UCS_F_ALWAYS_INLINE uint64_t uct_cxi_fc_pb_bits(uct_cxi_ep_t *ep,
                                                       uct_cxi_iface_t *iface)
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

/** Report the send's completion on the TX EQ (in the preceding c_state). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_cstate(struct c_cstate_cmd *cstate, uct_cxi_iface_t *iface)
{
    cstate->eq = iface->tx_eq.evtq->eqn;
}

/** Tag the completion with \a ep and the flow-control cost (in the message
 *  header: an unrestricted IDC ignores the c_state user_ptr). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_hdr(struct c_idc_msg_hdr *hdr, uct_cxi_ep_t *ep, unsigned cls,
                      unsigned units, int credited)
{
    ucs_assert(units <= UCT_CXI_USER_PTR_UNITS_MASK);
    hdr->user_ptr = uct_cxi_ep_short_user_ptr(ep) |
                    ((cls == UCT_CXI_FC_TAG) ? UCT_CXI_USER_PTR_TAG : 0) |
                    ((uint64_t)units << UCT_CXI_USER_PTR_UNITS_SHIFT) |
                    (credited ? UCT_CXI_USER_PTR_CREDITED : 0);
}

/** Account the send once it has been rung (undone by its completion). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_idc_track_commit(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface)
{
    uct_cxi_ep_tx_commit(ep, iface);
}

/** Slow path of uct_cxi_fc_reserve(): the peer is not (yet) up. */
BEGIN_C_DECLS
ucs_status_t uct_cxi_fc_reserve_slow(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                                     int *credited_p);
END_C_DECLS

/**
 * May a send of class \a cls costing \a slots and \a units go to this ep's
 * peer? \a *credited_p says whether it must be charged (not for LEGACY peers).
 * Else UCS_ERR_NO_RESOURCE (no credits, or handshake in flight) with
 * iface->tx.credit_block set.
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
static UCS_F_ALWAYS_INLINE void uct_cxi_fc_debit(uct_cxi_ep_t *ep, int credited,
                                                 unsigned cls, unsigned slots,
                                                 unsigned units)
{
    uct_cxi_peer_t *peer;

    if (credited) {
        peer                       = ep->peer;
        peer->tx.avail_slots      -= (int32_t)slots;
        peer->tx.avail_units[cls] -= (int32_t)units;
        peer->tx.used_slots       += slots;
        peer->tx.used_units[cls]  += units;
    }
}

/**
 * match_bits to piggyback on an Active Message to this ep's peer: the credits
 * we owe it, or 0 if less than a granule is owed (uct_cxi_fc_pb_sent() is the
 * other half).
 */
static UCS_F_ALWAYS_INLINE uint64_t uct_cxi_fc_pb_bits(uct_cxi_ep_t *ep,
                                                       uct_cxi_iface_t *iface)
{
    uct_cxi_peer_t *peer = ep->peer;
    const uint8_t *shift = iface->fc.pb_shift;
    uint64_t bits;
    unsigned cls;
    int owed;

    if (ucs_unlikely(peer == NULL)) {
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

/** The message carrying \a bits (uct_cxi_fc_pb_bits) has been rung. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_pb_sent(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, uint64_t bits)
{
    uct_cxi_peer_t *peer;
    const uint8_t *shift;
    unsigned cls;

    if (ucs_likely(bits == 0)) {
        return;
    }

    peer  = ep->peer;
    shift = iface->fc.pb_shift;
    uct_cxi_fc_pb_advance(&peer->rx.adv_slots, peer->rx.ret_slots, shift[0]);
    for (cls = 0; cls < UCT_CXI_FC_NUM_CLASSES; cls++) {
        uct_cxi_fc_pb_advance(&peer->rx.adv_units[cls], peer->rx.ret_units[cls],
                              shift[1 + cls]);
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
 * Send \a length bytes of \a data as one unrestricted IDC message to \a dfa,
 * counted against its ep and tracked by its completion. \a cls, \a units and
 * \a credited are its flow-control charge, which the caller applies;
 * \a header_data is 0 except for a tagged software rendezvous request.
 * UCS_ERR_NO_RESOURCE if the command queue is full, with nothing counted.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_ep_idc_send(
        uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, union c_fab_addr dfa,
        uint8_t idx_ext, uint64_t match_bits, uint64_t header_data,
        const void *data, size_t length, unsigned cls, unsigned units,
        int credited, const char *what)
{
    struct c_cstate_cmd cstate = {};
    struct c_idc_msg_hdr hdr   = {};
    int ret;

    cstate.event_send_disable = 1;
    cstate.initiator          = iface->match_id;
    cstate.index_ext          = idx_ext;
    uct_cxi_idc_track_cstate(&cstate, iface);

    ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, what, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    hdr.dfa         = dfa;
    hdr.match_bits  = match_bits;
    hdr.header_data = header_data;
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
void uct_cxi_ep_destroy(uct_ep_h tl_ep);

ucs_status_t
uct_cxi_ep_flush(uct_ep_h tl_ep, unsigned flags, uct_completion_t *comp);
ucs_status_t uct_cxi_ep_fence(uct_ep_h tl_ep, unsigned flags);

ucs_status_t
uct_cxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n, unsigned flags);
void uct_cxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg);

/* Arbiter callback: drains the ep's pending requests on progress. */
ucs_arbiter_cb_result_t
uct_cxi_ep_process_pending(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                           ucs_arbiter_elem_t *elem, void *arg);

#endif /* UCT_CXI_EP_H */
