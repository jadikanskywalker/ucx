/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload declarations.
 *
 * Uses Cassini's real matching-list capability (is_matching=1, sender's tag
 * compared via match_bits/ignore_bits) -- unlike the AM PTE, which is also
 * is_matching=1 but always wildcards (match_bits=0/ignore_bits=UINT64_MAX).
 *
 * Two independent pieces on one PTE (pid_offset = UCT_CXI_PTE_TAG):
 *   - Priority-list LEs, one per uct_iface_tag_recv_zcopy() call, use_once,
 *     bound to the caller's own registered destination buffer for direct
 *     hardware DMA (zero software copy on a direct match).
 *   - A true Portals4 overflow-list ring (C_PTL_LIST_OVERFLOW,
 *     unexpected_hdr_disable=0) catching messages with no matching
 *     priority LE posted yet -- structurally modeled on the AM PTE's
 *     buffer ring (contiguous alloc, buffer_id-indexed, manage_local), but
 *     genuinely new semantics: unexpected data is copied out immediately
 *     and handed to UCP's own SW tag-matching via eager_cb/rndv_cb, never
 *     retained waiting for a future post.
 */

#ifndef UCT_CXI_TAG_H
#define UCT_CXI_TAG_H

#include "cxi_ep.h"
#include <uct/api/uct.h>
#include <ucs/datastruct/queue.h>

/* min_free threshold for the overflow ring: a small fixed margin, matching
 * UCT_CXI_AM_MIN_FREE's already-proven pattern (see cxi_iface.h) rather
 * than scaling to the max eager size -- Cassini's manage_local placement
 * logic evidently handles an oversized-relative-to-remaining-space Put on
 * its own; a large fixed threshold is unvalidated and unnecessary here. */
#define UCT_CXI_TAG_OVF_MIN_FREE      256u

/* buffer_id (uint16_t) splits into three disjoint ranges: real priority-LE
 * slot ids [0, max_outstanding); one reserved *eager* SEARCH_AND_DELETE id
 * per overflow buffer, [BUFIDX_BASE, BUFIDX_BASE + num_bufs); and,
 * separately, one reserved *rendezvous* id per overflow buffer,
 * [RNDV_BUFIDX_BASE, + num_bufs) -- eager and rendezvous arrivals share the
 * same overflow ring but dispatch to different UCP callbacks (eager_cb vs
 * rndv_cb), so each buf_idx needs two distinct ids. num_bufs is capped at
 * UCT_CXI_TAG_OVF_NUM_BUFS_MAX so both split points stay fixed constants. */
#define UCT_CXI_TAG_OVF_NUM_BUFS_MAX      1024u
#define UCT_CXI_TAG_MAX_OUTSTANDING_MAX   \
        (65535u - (2u * UCT_CXI_TAG_OVF_NUM_BUFS_MAX))

/* Advertised rndv.max_hdr -- must be >= sizeof(ucp_tag_offload_unexp_
 * rndv_hdr_t) (17 bytes), which UCP sends with every offloaded rendezvous
 * send and asserts on unconditionally; reporting less would silently
 * disable the whole offloaded-rendezvous protocol, not just the
 * unexpected-arrival path this header now supports (see uct_ep_tag_rndv_
 * zcopy). 32 is comfortable margin. */
#define UCT_CXI_TAG_RNDV_MAX_HDR      32u

/* Base of the reserved buffer_id range used for our own SEARCH_AND_DELETE
 * commands -- one entry per overflow ring buffer (buf_idx), not one per
 * outstanding command or per arrival. uct_cxi_iface_tag_handle_ovf_
 * arrival() sets sd.buffer_id = BASE + buf_idx when it issues the command
 * for an arrival into that buffer; the confirmation's own buffer_id then
 * directly *is* buf_idx (minus BASE) -- no separate tracking table,
 * free-list, or ordering assumption needed.
 *
 * Why buffer_id and not match_bits (the tag): match_bits is not a safe
 * correlation key on its own -- the same tag can legitimately be
 * outstanding on multiple concurrent messages between a peer pair (normal
 * MPI/UCX usage), so two different arrivals could share it. buffer_id is a
 * field we assign ourselves, so it has no such collision risk.
 *
 * Why per-buffer-generation and not per-arrival: ovf_refcnt itself is
 * tracked per buf_idx, not per arrival (see cxi_iface.h's doc comment on
 * it) -- multiple arrivals into the same generation all just need to
 * decrement the *same* counter, so a shared per-buf_idx id is sufficient;
 * nothing needs to distinguish which specific arrival within a generation
 * a given confirmation belongs to.
 *
 * Why this exists at all (why the previous single shared sentinel wasn't
 * enough): with sd.use_once=1 (see tag_handle_ovf_arrival()'s own comment
 * on why that flag is now set), a "not found" outcome is confirmed via
 * C_EVENT_SEARCH alone, and that event's own event->tgt_long.start is
 * always 0 -- not a real address (empirically confirmed on real hardware,
 * test_cxi_tag_ovf.raw_event_order_and_manual_search_delete: 8/8 runs, a
 * "won" confirmation on the same command shape always carries a real,
 * correct start, a "lost" one always shows exactly 0x0). buf_idx cannot be
 * recovered from that event's own fields at all, so it has to be encoded
 * directly into the one field the command lets us choose ourselves. */
#define UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE  UCT_CXI_TAG_MAX_OUTSTANDING_MAX

/* Rendezvous counterpart of the range above -- see its own doc comment
 * (UCT_CXI_TAG_OVF_NUM_BUFS_MAX's comment) for why a disjoint range is
 * needed. Dispatched in cxi_iface.c's progress loop before ever falling
 * back to the eager SEARCH_AND_DELETE handlers. */
#define UCT_CXI_TAG_SEARCH_DELETE_RNDV_BUFIDX_BASE \
        (UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE + UCT_CXI_TAG_OVF_NUM_BUFS_MAX)

/* uct_cxi_tag_ctx_priv_t::rndv_flags bits 1-3 -- per-event bookkeeping for
 * a rendezvous receive (pre-shifted to land directly in rndv_flags).
 *
 * All three of Put/Put_Overflow, Rendezvous, and Reply are required before
 * completing, matching libfabric's rdzv_recv_req_event()
 * (cxip_msg_hpc.c:307-320): "After three events, a rendezvous receive is
 * complete... Put, Rendezvous, Reply -- or Put Overflow, Rendezvous,
 * Reply."
 *
 * This was previously relaxed to just SEEN_RNDV|SEEN_REPLY, on an earlier
 * hardware finding that our rendezvous Put -- always eager_length=0 (see
 * uct_ep_tag_rndv_zcopy) -- supposedly never generates its own
 * C_EVENT_PUT/C_EVENT_PUT_OVERFLOW at all, making SEEN_PUT permanently
 * unreachable. Direct empirical re-testing (test_cxi_tag_rndv.
 * direct_match_small and delayed_match_get_issued, both with
 * UCX_LOG_LEVEL=debug) contradicts that: both direct-match and delayed-
 * match rendezvous receives reliably generate a real Put/Put_Overflow
 * event ("[DIRECT-MATCH-RNDV]"/"[OVF-MATCHED-RNDV]" in the debug log),
 * consistent with libfabric's own reliance on zero-byte Puts as a fence/
 * signal mechanism elsewhere in its design -- there is no fundamental
 * reason eager_length=0 would suppress the event. The earlier "permanent
 * hang" was very likely caused by something else already fixed since (the
 * O(1) match_bits redesign or the CXI_MATCH_ID_ANY fix are the most likely
 * candidates), not by SEEN_PUT being unreachable. Reverted back to
 * requiring all three -- re-validated via full test_cxi_tag_rndv
 * regression, not just these two tests, specifically watching for any
 * reintroduced hang. */
enum {
    UCT_CXI_RNDV_SEEN_PUT     = UCS_BIT(1), /* C_EVENT_PUT or C_EVENT_PUT_OVERFLOW */
    UCT_CXI_RNDV_SEEN_RNDV    = UCS_BIT(2), /* C_EVENT_RENDEZVOUS */
    UCT_CXI_RNDV_SEEN_REPLY   = UCS_BIT(3), /* C_EVENT_REPLY (get_issued 0 or 1) */
    UCT_CXI_RNDV_SEEN_REQUIRED = UCT_CXI_RNDV_SEEN_PUT | UCT_CXI_RNDV_SEEN_RNDV |
                                 UCT_CXI_RNDV_SEEN_REPLY
};

/*
 * Private per-request state stored in uct_tag_context_t::priv
 * (UCT_TAG_PRIV_LEN = 32 bytes available).
 */
typedef struct uct_cxi_tag_ctx_priv {
    uint16_t slot;            /* Index into iface->tag.ctx[]/free_list[] */
    uint8_t  rndv_flags;      /* Packed to fit UCT_TAG_PRIV_LEN=32 bytes:
                             * bit 0     = is_rndv, latched from the first
                             *             event seen on this slot (either
                             *             event->tgt_long.rendezvous, or the
                             *             event type being C_EVENT_RENDEZVOUS
                             *             itself). 0 => plain eager, complete
                             *             on the first (only) event as
                             *             before. 1 => hold for
                             *             rndv_seen==SEEN_ALL.
                             * bits 1-4  = UCT_CXI_RNDV_SEEN_* accumulated so
                             *             far (only meaningful if bit 0 set).
                             * bit 5     = truncated (rlength > mlength),
                             *             latched from whichever tgt_long
                             *             event arrives (Put/Put_Overflow/
                             *             Rendezvous all carry the same
                             *             rlength/mlength for one message).
                             * imm (header_data) needs no persistence: for
                             * eager it's read from the event and used
                             * immediately (single-event completion); for
                             * rendezvous the UCT API doc guarantees it's
                             * always 0, so the final completed_cb call just
                             * passes a literal 0. The destination address
                             * for a software-issued Get is likewise read
                             * directly off the C_EVENT_RENDEZVOUS event
                             * (event->tgt_long.start) at the point it's
                             * needed, not persisted here. */
    uint64_t stag;            /* match_bits -- completed_cb's stag argument.
                             * For eager, read from the event and used
                             * immediately; for rendezvous, persisted across
                             * the 3-event wait since any of the three could
                             * be last to arrive. */
    uint32_t length;          /* Final total message length (rlength -- the
                             * full request_len, not just the eager-attached
                             * portion). Same persistence rationale as stag. */
    uint32_t posted_len;      /* Capacity of the buffer posted at
                             * tag_recv_zcopy time (iov[0].length), i.e. the
                             * LE's own le.length. A rendezvous Put always
                             * carries eager_length=0 on this transport, so
                             * event->tgt_long.mlength is 0 throughout --
                             * unlike plain eager, truncation can't be
                             * detected from mlength/rlength alone and must
                             * be compared against this instead. Confirmed
                             * via libfabric's own issue_rdzv_get()
                             * (cxip_msg_hpc.c:369-457): it computes
                             * req->data_len = MIN(req->recv.ulen,
                             * event->tgt_long.rlength) before issuing the
                             * pull, and clamps cmd.request_len to
                             * (data_len - mlen) -- the posted buffer's own
                             * length is the only thing that bounds a
                             * software-issued Get, never rlength alone. */
    uint64_t recv_addr;       /* CPU pointer (iov[0].buffer at tag_recv_zcopy
                             * time), not an IOVA -- needed only for the
                             * explicit software copy on a delayed eager
                             * match (C_EVENT_PUT_OVERFLOW): Portals4 never
                             * retroactively re-targets an already-placed
                             * Put's DMA into a later-posted LE, so hardware
                             * has not moved the bytes here itself; see
                             * uct_cxi_iface_tag_handle_eager_match(). Unused
                             * for a direct match (C_EVENT_PUT) or for
                             * rendezvous (the Get's own local_addr always
                             * targets the real destination fresh, computed
                             * at pull time, regardless of match timing). */
} uct_cxi_tag_ctx_priv_t;

/* uct_cxi_tag_ctx_priv_t::rndv_flags bit layout (bits 1-4 are
 * UCT_CXI_RNDV_SEEN_* above). */
#define UCT_CXI_RNDV_FLAG_IS_RNDV     UCS_BIT(0)
#define UCT_CXI_RNDV_FLAG_TRUNCATED   UCS_BIT(5)

/* Hard ceiling on iface->rdzv.max_outstanding: the id has to survive a hop
 * through the original Put's own cmd.rendezvous_id field (struct
 * c_full_dma_cmd, cassini_user_defs.h), which is uint8_t. Not a UCX-chosen
 * limit -- it's the width of the actual hardware field carrying it. */
#define UCT_CXI_RDZV_MAX_OUTSTANDING_MAX  256u

/*
 * Per-send tracking for an outstanding uct_ep_tag_rndv_zcopy() exposure.
 * The opaque handle UCP holds (returned from rndv_zcopy, passed back to
 * rndv_cancel) *is* this pointer -- specifically &iface->rdzv.ops[id], a
 * plain fixed-size array (not a pool), indexed by the same small dense id
 * this struct's own `id` field holds.
 *
 * Correlation design mirrors libfabric's own DEFAULT rendezvous protocol
 * (cxip_msg_hpc.c's issue_rdzv_get()/cxip_rdzv_pte_src_cb(), *not* the
 * ALT_READ variant), traced and confirmed against real hardware this
 * session -- an address-based linear scan was tried first and worked, but
 * doesn't scale to high concurrency; a match_bits-embedded id on a
 * *restricted* Get was tried next and confirmed NOT to work (a restricted
 * command's actual wire packet, struct c_port_restricted_hdr,
 * cassini_user_defs.h:2799, has no match_bits field at all -- nothing we
 * put there can reach the target, regardless of what partial-looking data
 * seemed to come back). What actually works, matching DEFAULT exactly:
 *   1. iface->rdzv.pte is a *matching* PTE (is_matching=1) with one
 *      persistent, fully-wildcarded catch-all LE (match_bits=0,
 *      ignore_bits=~0) -- we have nothing to disambiguate being LAC-0-only,
 *      matching mode is used purely to get onto the wire format
 *      (c_port_unrestricted_hdr) that actually carries match_bits.
 *   2. This op's `id` (this struct's own index in iface->rdzv.ops[]) is
 *      stamped into the original Put's cmd.rendezvous_id.
 *   3. The receiver reads that back off its own RENDEZVOUS event
 *      (event->tgt_long.rendezvous_id -- populated because our Put is
 *      unrestricted) and stamps it into its own Get's cmd.match_bits
 *      (uct_cxi_iface_issue_rdzv_get, cmd.restricted=0 for this same
 *      reason) -- or, for a NIC-auto-issued Get (get_issued==1), hardware
 *      does this same propagation itself, the same way libfabric's own
 *      cxip_rdzv_pte_src_cb() decodes match_bits identically regardless of
 *      which get_issued outcome produced the event.
 *   4. That Get's resulting C_EVENT_GET on our own matching LE reports
 *      match_bits genuinely (unlike the restricted case), letting
 *      uct_cxi_iface_tag_handle_rdzv_get index straight into
 *      iface->rdzv.ops[id] -- O(1), no scan.
 *
 * `op` must be first -- same precedent as uct_cxi_rdzv_get_op_t below.
 * Confirmed on real hardware (a segfault, root-caused via gdb) and against
 * libfabric's own _cxip_send_rdzv_put()/cxip_send_rdzv_put_cb()
 * (cxip_msg_hpc.c:4490-4600,4347-4390): C_CMD_RENDEZVOUS_PUT generates a
 * real C_EVENT_ACK for its own local completion despite
 * event_send_disable=1 -- libfabric explicitly registers a callback for it
 * too, so this isn't a flag we're missing, it's simply not honored for
 * this opcode. That ACK's user_ptr flows through cxi_iface.c's generic
 * ACK/REPLY dispatch, which unconditionally casts it to
 * uct_cxi_send_op_t* -- so this struct must actually be one, not just be
 * castable-by-accident. See uct_cxi_rdzv_put_ack_comp in cxi_tag.c: the
 * ACK isn't the real completion signal on success (that's the peer's later
 * Get, still tracked below exactly as before) -- confirmed via
 * cxi_prov_hw.h's cxi_event_rc(): C_EVENT_GET is a *target* event (fires on
 * us) and C_EVENT_REPLY an *initiator* event (fires on the peer), and both
 * already propagate a failed cxi_event_rc() through to completed_cb on
 * their own, independent of this ACK. So on success uct_cxi_rdzv_put_ack_comp
 * must never free this op or fire `comp`. On failure, though, the Put
 * itself never landed -- no Get will ever be issued, so nothing else will
 * ever complete this op -- so the handler does fail it: returns the id to
 * iface->rdzv.free_ids[], fires `comp` with the error. Matches libfabric's
 * own rdzv_send_req_complete() on a bad ACK (cxip_msg_hpc.c:4386-4389).
 */
typedef struct uct_cxi_rdzv_op {
    uct_cxi_send_op_t op;      /* must be first; op.ep is the real, owning
                                   ep (unlike uct_cxi_rdzv_get_op_t below,
                                   this op has one) so the generic ACK
                                   dispatch's ep->outstanding/iface->tx.
                                   outstanding/flush bookkeeping applies
                                   normally, matching the ep->outstanding++/
                                   iface->tx.outstanding++ done at send time.
                                   op.comp unused (this struct's own `comp`
                                   below is the real one), op.handler =
                                   uct_cxi_rdzv_put_ack_comp */
    uct_completion_t *comp;    /* caller's own completion -- normally fired
                                   later from uct_cxi_iface_tag_handle_
                                   rdzv_get once the peer's Get lands; fired
                                   early with an error from
                                   uct_cxi_rdzv_put_ack_comp if the Put
                                   itself failed to land */
    uint32_t          length;
    uint8_t           id;      /* this op's index in iface->rdzv.ops[] --
                                   see the correlation design above */
    uint8_t           valid;   /* 0 once freed (completed or cancelled) --
                                   guards a stale/duplicate C_EVENT_GET the
                                   same way the old STALE-drop path did */
} uct_cxi_rdzv_op_t;

/*
 * Tracking for a software-issued (get_issued==0) rendezvous Get, allocated
 * from iface->tag.rdzv_get_op_pool. `op` must be first -- mirrors
 * uct_cxi_send_desc_t's own precedent (cxi_ep.h) -- so the existing
 * C_EVENT_REPLY dispatch in cxi_iface.c's progress loop, which
 * unconditionally casts event->init_short.user_ptr to (uct_cxi_send_op_t*)
 * and calls op->handler, works unmodified; uct_cxi_rdzv_get_comp (this
 * op's handler) then recovers `slot` via the same cast.
 */
typedef struct uct_cxi_rdzv_get_op {
    uct_cxi_send_op_t op;   /* must be first */
    uct_cxi_iface_t  *iface; /* op.ep is NULL -- no uct_cxi_ep_t exists for
                              * the peer that sent the original rendezvous
                              * Put, tag receives are posted on the iface,
                              * not a specific ep -- so the handler needs
                              * its own way back to the iface. */
    uint16_t          slot; /* priority-LE slot this Get belongs to */
} uct_cxi_rdzv_get_op_t;

/* Cancel is a bare software-tracking removal, no hardware operation at all
 * -- confirmed safe via the UCT API doc (uct_ep_tag_rndv_cancel() disregards
 * the op "without calling completion callback", precondition requires the
 * handle be "not completed yet" *at the time of the call*, which is UCP's
 * obligation to uphold) and rc_mlx5's own real implementation
 * (uct_rc_mlx5_ep_tag_rndv_cancel(): unconditional ucs_ptr_array_remove, no
 * hardware query). See the design plan's "Current increment" section for
 * the full reasoning on why this can never race a real Get. */


/* PTE lifecycle -- called from cxi_iface.c's UCS_CLASS_INIT/CLEANUP_FUNC.
 * open_tag_pte is a no-op (returns UCS_OK, iface->tag.pte stays NULL) if
 * UCP didn't supply both HW_TM callbacks or UCX_CXI_TAG_ENABLE=no -- UCP
 * transparently falls back to SW tag matching over AM in that case. */
ucs_status_t uct_cxi_iface_open_tag_pte(uct_cxi_iface_t *self,
                                         struct cxil_lni *lni,
                                         const uct_cxi_iface_config_t *config,
                                         const uct_iface_params_t *params);
void uct_cxi_iface_close_tag_pte(uct_cxi_iface_t *self);

/*
 * Rendezvous source-exposure PTE lifecycle -- opened whenever tag offload
 * is enabled (rendezvous has no meaning without it). Mapped at the
 * device's own rdzv_get_idx, not a self-chosen pid_idx -- see
 * uct_cxi_iface_open_rdzv_pte's own comment (cxi_tag.c) for why.
 * Matching (DEFAULT-protocol style, like libfabric's own rendezvous
 * source PTE), one persistent, fully-wildcarded whole-LAC catch-all LE.
 * See cxi_tag.c and uct_cxi_rdzv_op_t's own doc comment for the full
 * design and why this replaced an earlier restricted/address-routed
 * approach.
 */
ucs_status_t uct_cxi_iface_open_rdzv_pte(uct_cxi_iface_t *self,
                                          struct cxil_lni *lni);
void uct_cxi_iface_close_rdzv_pte(uct_cxi_iface_t *self);

/*
 * Event dispatch, called from cxi_iface.c's iface_progress() once it has
 * identified event->tgt_long.ptlte_index == iface->tag.pte->ptn.
 *
 * C_EVENT_PUT fires for BOTH LE populations on this one PTE and must be
 * further split by event->tgt_long.ptl_list (the caller's job, since it
 * already branches on ptlte_index):
 *   - C_PTL_LIST_OVERFLOW -> tag_handle_ovf_arrival (unexpected message
 *     landed with no priority LE posted for it yet).
 *   - C_PTL_LIST_PRIORITY -> a direct match: a priority LE was already
 *     posted, data landed straight into the caller's buffer.
 * A direct match (C_EVENT_PUT/ptl_list==PRIORITY) and a delayed-
 * correlation match (C_EVENT_PUT_OVERFLOW: the message had already landed
 * in the overflow ring before this priority LE was posted) carry
 * identical fields and need identical disposition either way -- the only
 * remaining question, for *either* one, is whether
 * event->tgt_long.rendezvous is set. That classification, plus routing a
 * genuine C_EVENT_RENDEZVOUS (also carries event->tgt_long.buffer_id ==
 * the same priority-LE slot), is the caller's job (iface_progress() in
 * cxi_iface.c, which already has to inspect ptl_list/event_type anyway to
 * decide which branch to take) -- not something either handler below
 * re-derives:
 *   - tag_handle_eager_match: plain eager, completes on this one event.
 *   - tag_handle_rdzv_match: rendezvous. See UCT_CXI_RNDV_SEEN_* above --
 *     a rendezvous receive accumulates all three events (Put/Put_Overflow,
 *     Rendezvous, Reply) before completed_cb fires; this handler is the
 *     entry point for the first two, uct_cxi_iface_tag_handle_rdzv_reply
 *     (below) for the third when get_issued==1 (NIC auto-issued, no
 *     corresponding uct_cxi_send_op_t exists to dispatch through the
 *     ordinary tx-completion path) -- the get_issued==0 case instead
 *     reuses that ordinary path (op->handler), needing no separate entry
 *     point here.
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event);
/* Dispatched from cxi_iface.c for a C_EVENT_PUT_OVERFLOW whose buffer_id
 * falls in the reserved eager SEARCH_AND_DELETE range (see UCT_CXI_TAG_
 * SEARCH_DELETE_BUFIDX_BASE), before choosing between eager and rendezvous
 * match handling. With sd.use_once=1, this event only ever fires "found and
 * deleted" (C_RC_OK) -- "not found" is C_EVENT_SEARCH, see
 * uct_cxi_iface_tag_handle_search_delete_not_found() below. */
void uct_cxi_iface_tag_handle_search_delete_confirm_eager(uct_cxi_iface_t *iface,
                                                    const union c_event *event);
/* Rendezvous counterpart of the above, for the disjoint RNDV_BUFIDX_BASE
 * range: calls rndv_cb instead of eager_cb, and reconstructs/caches the
 * unexpected-rndv header (uct_cxi_rndv_peer_hdr_t) instead of just copying
 * raw eager bytes. */
void uct_cxi_iface_tag_handle_search_delete_confirm_rndv(
        uct_cxi_iface_t *iface, const union c_event *event);

void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event);
void uct_cxi_iface_tag_handle_rdzv_match(uct_cxi_iface_t *iface,
                                         const union c_event *event);
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                      const union c_event *event);

/*
 * uct_cxi_iface_tag_handle_rdzv_reply -- C_EVENT_REPLY with
 * event->init_short.rendezvous==1 (a hardware/NIC auto-issued rendezvous
 * Get completed; get_issued==0 software-issued Gets complete via the
 * ordinary tx uct_cxi_send_op_t::handler path instead and never reach
 * here). Called from cxi_iface.c's iface_progress() before its normal
 * C_EVENT_REPLY/user_ptr-as-pointer handling, since this event's user_ptr
 * is not a pointer at all -- it's a struct cxi_rdzv_user_ptr bit-packed
 * value (cxi_prov_hw.h:490-501) whose buffer_id sub-field is the same
 * priority-LE slot tag_handle_match() itself dispatches on.
 */
void uct_cxi_iface_tag_handle_rdzv_reply(uct_cxi_iface_t *iface,
                                         const union c_event *event);

/*
 * uct_cxi_rdzv_put_ack_comp -- uct_cxi_send_op_t::handler for a rendezvous
 * Put's own local C_EVENT_ACK (see uct_cxi_rdzv_op_t's doc comment above
 * for why this event exists at all despite event_send_disable=1, and for
 * why success and failure are handled differently here).
 */
void uct_cxi_rdzv_put_ack_comp(uct_cxi_send_op_t *op, ucs_status_t status);

/*
 * uct_cxi_iface_tag_handle_rdzv_get -- C_EVENT_GET on iface->rdzv.pte (a
 * peer's Get read from our exposed catch-all LE, i.e. the send side of a
 * rendezvous transfer completing). Called from cxi_iface.c's
 * iface_progress() once it has identified
 * event->tgt_long.ptlte_index == iface->rdzv.pte->ptn.
 */
void uct_cxi_iface_tag_handle_rdzv_get(uct_cxi_iface_t *iface,
                                       const union c_event *event);

/*
 * uct_cxi_rdzv_get_comp -- uct_cxi_send_op_t::handler for a software-issued
 * (get_issued==0) rendezvous Get's C_EVENT_REPLY. Mirrors
 * uct_cxi_get_bcopy_comp's role (cxi_rma.c) but completes the *receive*
 * side's tag_handle_match() accounting (UCT_CXI_RNDV_SEEN_REPLY) instead of
 * an RMA get_bcopy caller.
 */
void uct_cxi_rdzv_get_comp(uct_cxi_send_op_t *op, ucs_status_t status);

/*
 * Mirrors ucp_tag_offload_unexp_rndv_hdr_t's exact layout (ucp/tag/
 * offload.h: uint64_t ep_id; uint64_t req_id; uint8_t md_index;), duplicated
 * here rather than included -- uct must not depend on ucp (see src/
 * AGENTS.md's layer boundaries). UCS_S_PACKED makes this byte-for-byte
 * identical to the real header, so the raw bytes UCP hands to/expects from
 * this transport can be reinterpreted as this struct directly, with named
 * field access instead of manual offset arithmetic. ep_id and md_index are
 * constant for the life of a UCP connection and travel once, via a
 * dedicated control message (uct_cxi_ep_send_rndv_hdr_announce, cxi_am.c);
 * req_id is the only field that varies per send and travels via header_data
 * on every rendezvous Put -- see uct_ep_tag_rndv_zcopy and iface->tag.
 * rndv_peer_cache (cxi_iface.h).
 */
typedef struct uct_cxi_rndv_hdr_wire {
    uint64_t ep_id;
    uint64_t req_id;
    uint8_t  md_index;
} UCS_S_PACKED uct_cxi_rndv_hdr_wire_t;

/*
 * uct_cxi_rndv_unexp_pending_t -- a SEARCH_AND_DELETE confirmation for a
 * genuinely-unexpected rendezvous arrival whose initiator's one-time header
 * announce (uct_cxi_ep_send_rndv_hdr_announce) hasn't been processed yet.
 * The announce and the rendezvous Put are two independent wire sends with
 * no guaranteed relative arrival order (same reasoning that already rules
 * out C_CMD_CQ_FENCE elsewhere in this transport as a target-arrival-order
 * fix), so a cache miss in uct_cxi_iface_tag_handle_search_delete_confirm_
 * rndv() is a legitimate race, not an error: this struct parks everything
 * needed to complete the rndv_cb call later, once uct_cxi_iface_handle_
 * rndv_hdr_announce() populates iface->tag.rndv_peer_cache for this
 * initiator and drains iface->tag.rndv_unexp_pending_q.
 */
typedef struct uct_cxi_rndv_unexp_pending {
    ucs_queue_elem_t queue;         /* intrusive link */
    uint32_t         initiator;    /* event->tgt_long.initiator.initiator.process */
    uint64_t         tag;          /* event->tgt_long.match_bits */
    uint64_t         remote_offset;
    uint32_t         rlength;
    uint64_t         header_data;  /* req_id -- see uct_cxi_rndv_hdr_wire_t */
    uint8_t          rendezvous_id;
} uct_cxi_rndv_unexp_pending_t;

/*
 * uct_cxi_iface_handle_rndv_hdr_announce -- receive-side handler for the
 * one-time-per-ep control message sent by uct_cxi_ep_send_rndv_hdr_announce
 * (cxi_am.c). Called from cxi_iface.c's AM dispatch when event->tgt_long.
 * match_bits has UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG set, before ever reaching
 * uct_iface_invoke_am(). Populates iface->tag.rndv_peer_cache for this
 * initiator, then drains iface->tag.rndv_unexp_pending_q for it.
 */
void uct_cxi_iface_handle_rndv_hdr_announce(uct_cxi_iface_t *iface,
                                             const union c_event *event,
                                             const void *payload,
                                             uint32_t len);

/* UCT tag-matching ops -- installed into uct_cxi_iface_ops in cxi_iface.c.
 * eager_short/bcopy/zcopy and tag_recv_zcopy/cancel are Phase A.
 * ep_tag_rndv_zcopy/cancel/request are Phase B (this increment) -- see the
 * design plan's "Current increment" and Part 1 sections. */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length);

ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                    uint64_t imm, uct_pack_callback_t pack_cb,
                                    void *arg, unsigned flags);

ucs_status_t uct_cxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp);

ucs_status_t uct_cxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx);

ucs_status_t uct_cxi_iface_tag_recv_cancel(uct_iface_h tl_iface,
                                           uct_tag_context_t *ctx, int force);

ucs_status_ptr_t uct_cxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                           const void *header,
                                           unsigned header_length,
                                           const uct_iov_t *iov,
                                           size_t iovcnt, unsigned flags,
                                           uct_completion_t *comp);

ucs_status_t uct_cxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *op);

ucs_status_t uct_cxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length,
                                         unsigned flags);

#endif /* UCT_CXI_TAG_H */
