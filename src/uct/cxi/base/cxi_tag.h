/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload declarations.
 *
 * One PTE (pid_offset = UCT_CXI_PTE_TAG) with real matching and two LE
 * populations:
 *   - use_once priority LEs, one per uct_iface_tag_recv_zcopy(), bound to the
 *     caller's buffer for a zero-copy direct match;
 *   - an overflow ring (C_PTL_LIST_OVERFLOW) for messages with no receive
 *     posted yet, handed to UCP's software matching via eager_cb/rndv_cb.
 */

#ifndef UCT_CXI_TAG_H
#define UCT_CXI_TAG_H

#include "cxi_ep.h"
#include <uct/api/uct.h>
#include <ucs/datastruct/queue.h>


/*
 * The overflow ring's min_free is the largest eager message (tag.max_msg): a
 * Put that does not fit what is left of its buffer fails with NO_SPACE rather
 * than try the next. Limited to UCT_CXI_AM_MAX_MSG_LIMIT by the 24-bit field.
 */

/* Cap on the number of overflow ring buffers (TAG_OVERFLOW_NUM_BUFS). */
#define UCT_CXI_TAG_OVF_NUM_BUFS_MAX 1024u

/* The buffers are at least this, and four times the largest message if that is
 * more, as for the AM ring. */
#define UCT_CXI_TAG_OVF_BUF_SIZE_MIN (1024u * 1024u)
#define UCT_CXI_TAG_OVF_BUF_PER_MSG  4u

/*
 * Events a posted receive can leave in the RX EQ: the match (or delayed
 * match), the rendezvous and its pull's completion. A cancel losing to a match
 * adds one, which the slack takes.
 */
#define UCT_CXI_TAG_RECV_EVENTS 3u

/* The most unexpected messages tracked at once, whatever the credits allow. */
#define UCT_CXI_TAG_UNEXP_MAX_LIMIT (1u << 20)

/*
 * buffer_id comes back on events: priority-LE slots are [0, max_outstanding)
 * and the two ids above are our SEARCH_AND_DELETE and fence commands.
 */
#define UCT_CXI_TAG_MAX_OUTSTANDING_MAX 65533u

/*
 * Size of the ring of receives that may still take a message already in the
 * overflow list (uct_cxi_tag_pend_t), a power of two. A full ring refuses
 * receives, which UCP then matches in software.
 */
#define UCT_CXI_TAG_PEND_SIZE 512u

/* The most fences in flight: each leaves one event, covered by the reserve. */
#define UCT_CXI_TAG_FENCE_MAX_INFLIGHT 32u

/*
 * header_data of a tagged Put that is a software rendezvous request
 * (uct_ep_tag_rndv_request): its payload is UCP's RTS and goes to rndv_cb with
 * no remote address. No eager message carries it, as with InfiniBand TM's
 * immediate 0.
 */
#define UCT_CXI_TAG_SW_RNDV_IMM UINT64_MAX

/* Advertised rndv.max_hdr, at least sizeof(ucp_tag_offload_unexp_rndv_hdr_t) */
#define UCT_CXI_TAG_RNDV_MAX_HDR 32u

/*
 * buffer_id of our SEARCH_AND_DELETE commands, telling their events apart from
 * priority-LE events (a delayed match is also a C_EVENT_PUT_OVERFLOW).
 */
#define UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID UCT_CXI_TAG_MAX_OUTSTANDING_MAX

/* buffer_id of the fences: a search matching nothing (uct_cxi_tag_pend_t). */
#define UCT_CXI_TAG_FENCE_BUFFER_ID (UCT_CXI_TAG_MAX_OUTSTANDING_MAX + 1u)

/*
 * uct_cxi_tag_ctx_priv_t::rndv_flags bits 1-3, pre-shifted. A rendezvous
 * receive completes after all of Put/Put_Overflow, Rendezvous and Reply, as in
 * libfabric's rdzv_recv_req_event().
 */
enum {
    /* C_EVENT_PUT or C_EVENT_PUT_OVERFLOW */
    UCT_CXI_RNDV_SEEN_PUT      = UCS_BIT(1),
    /* C_EVENT_RENDEZVOUS */
    UCT_CXI_RNDV_SEEN_RNDV     = UCS_BIT(2),
    /* C_EVENT_REPLY (get_issued 0 or 1) */
    UCT_CXI_RNDV_SEEN_REPLY    = UCS_BIT(3),
    UCT_CXI_RNDV_SEEN_REQUIRED = UCT_CXI_RNDV_SEEN_PUT |
                                 UCT_CXI_RNDV_SEEN_RNDV |
                                 UCT_CXI_RNDV_SEEN_REPLY
};

/*
 * Private per-request state in uct_tag_context_t::priv (UCT_TAG_PRIV_LEN).
 * The rendezvous fields are kept across the three events of a rendezvous.
 */
typedef struct uct_cxi_tag_ctx_priv {
    /* Index into iface->tag.ctx[] and free_list[] */
    uint16_t slot;
    /*
     * Bit 0 is_rndv, latched from the first event; bits 1-3
     * UCT_CXI_RNDV_SEEN_* so far; bit 5 truncated (rlength > mlength); bit 6
     * UCT_CXI_TAG_FLAG_CONSUMED. imm is not kept: it is 0 for a rendezvous.
     */
    uint8_t  rndv_flags;
    /* completed_cb's stag */
    uint64_t stag;
    /* Total message length (rlength) */
    uint32_t length;
    /*
     * Capacity of the posted buffer (the LE's length). A rendezvous Put carries
     * eager_length 0, so mlength is 0 and truncation is checked against this.
     */
    uint32_t posted_len;
    /*
     * CPU pointer of the posted buffer, for the software copy of a delayed
     * eager match. Unused for a direct match and for a rendezvous.
     */
    uint64_t recv_addr;
} uct_cxi_tag_ctx_priv_t;

/*
 * Other rndv_flags bits. CONSUMED: UCP was told via tag_consumed_cb that this
 * receive is taken, once (uct_cxi_tag_claim), eager receives too.
 */
#define UCT_CXI_RNDV_FLAG_IS_RNDV   UCS_BIT(0)
#define UCT_CXI_RNDV_FLAG_TRUNCATED UCS_BIT(5)
#define UCT_CXI_TAG_FLAG_CONSUMED   UCS_BIT(6)

/* Ceiling on rdzv.max_outstanding: the id passes through an 8-bit field. */
#define UCT_CXI_RDZV_MAX_OUTSTANDING_MAX 256u

/*
 * An outstanding uct_ep_tag_rndv_zcopy() exposure; UCP's handle is
 * &iface->rdzv.ops[id].
 *
 * Correlation, as libfabric's default rendezvous protocol:
 *   1. iface->rdzv.pte is a matching PTE with one wildcard LE; matching mode
 *      only puts the Get on the wire format that carries match_bits.
 *   2. The Put carries this op's id in cmd.rendezvous_id.
 *   3. The receiver reads it from its RENDEZVOUS event and stamps it into its
 *      Get's match_bits (hardware does the same for an auto-issued Get).
 *   4. The resulting C_EVENT_GET reports match_bits, so
 *      uct_cxi_iface_tag_handle_rdzv_get indexes ops[id] directly. It completes
 *      the op, except for a Get that UCP issued for an unexpected rendezvous
 *      (UCT_CXI_RDZV_MATCH_SW_PULL): UCP's ATS cancels that op instead.
 *
 * `op` must be first: C_CMD_RENDEZVOUS_PUT raises an ACK despite
 * event_send_disable, and the generic dispatch casts its user_ptr to a send op.
 * On success that ACK completes nothing (the peer's Get does); on failure no
 * Get will come, so uct_cxi_rdzv_put_ack_comp frees the id and fires `comp`
 * with the error.
 */
typedef struct uct_cxi_rdzv_op {
    /* op.ep is the owning ep; op.handler is uct_cxi_rdzv_put_ack_comp */
    uct_cxi_send_op_t op;
    /* Caller's completion, fired by tag_handle_rdzv_get or on a failed ACK */
    uct_completion_t  *comp;
    uint32_t          length;
    /* This op's index in iface->rdzv.ops[] */
    uint8_t           id;
    /* 0 once freed, guarding against a stale or duplicate C_EVENT_GET */
    uint8_t           valid;
} uct_cxi_rdzv_op_t;

/*
 * A software-issued (get_issued 0) rendezvous Get, from
 * iface->tag.rdzv_get_op_pool. `op` must be first so the generic REPLY
 * dispatch calls op->handler (uct_cxi_rdzv_get_comp).
 */
typedef struct uct_cxi_rdzv_get_op {
    uct_cxi_send_op_t op;
    /* Receives belong to the iface, not an ep (op.ep is NULL) */
    uct_cxi_iface_t   *iface;
    /* Priority-LE slot this Get belongs to */
    uint16_t          slot;
} uct_cxi_rdzv_get_op_t;

/*
 * Layout of ucp_tag_offload_unexp_rndv_hdr_t, duplicated since uct must not
 * depend on ucp. ep_id and md_index are constant per connection and travel once
 * in the announce (uct_cxi_ep_send_rndv_hdr_announce); req_id varies and
 * travels in the header_data of every rendezvous Put.
 */
typedef struct uct_cxi_rndv_hdr_wire {
    uint64_t ep_id;
    uint64_t req_id;
    uint8_t  md_index;
} UCS_S_PACKED uct_cxi_rndv_hdr_wire_t;

/*
 * An entry of a stream: an unexpected message that is UCP's and must wait
 * before it can be reported in order, or a tombstone.
 *
 * Who owns an unexpected message is decided on arrival
 * (uct_cxi_iface_tag_handle_ovf_arrival): a posted receive claims it, or UCP is
 * told at once, except for a rendezvous: UCP needs the sender's source address,
 * which the hardware does not give us, so it is read from the sender's address
 * table (iface->rdzv.addr_table) with an 8-byte RMA Get. State NEW -> READING
 * -> READY, or FAILED.
 *
 * UCP matches unexpected messages in report order, so a later message with the
 * same tag from the same sender is held behind one whose address is in flight.
 * Each (sender, tag) has a stream (uct_cxi_unexp_stream_t, in
 * iface->tag.unexp_streams) chaining its held messages in arrival order; only
 * the head is reported.
 *
 * A tombstone (UCT_CXI_UNEXP_LOST) stands for a message a receive took (its
 * delayed match) before the arrival was seen; the two events come from
 * different NIC pipelines, in either order. A tombstone is never read, and for
 * a cancelled receive the message goes to UCP after all
 * (UCT_CXI_UNEXP_REDELIVER).
 *
 * `op` must be first, as for uct_cxi_rdzv_get_op_t: the read's REPLY calls
 * op->handler for an op without an ep. Entries are registered memory, as
 * `value` is where the read lands.
 */

/* Rendezvous: address read not posted yet */
#define UCT_CXI_UNEXP_NEW 0
/* Rendezvous: address read in flight */
#define UCT_CXI_UNEXP_READING 1
/* Eager, or rendezvous with its address */
#define UCT_CXI_UNEXP_READY 2
/* Rendezvous: the address read failed */
#define UCT_CXI_UNEXP_FAILED 3

/* Flags: a tombstone */
#define UCT_CXI_UNEXP_LOST 1
/* Flags: a tombstone of an eager message to report to UCP on arrival */
#define UCT_CXI_UNEXP_REDELIVER 2

typedef struct uct_cxi_unexp_report {
    /* What is looked at along a stream's chain is in the first cache line */
    uct_cxi_send_op_t           op;
    /* stream->entries, arrival order */
    ucs_list_link_t             link;
    /* Not valid once off the chain */
    struct uct_cxi_unexp_stream *stream;
    /* The event's rendezvous_id */
    uint8_t                     rendezvous_id;
    uint8_t                     is_rndv;
    /* UCT_CXI_UNEXP_{NEW,...} */
    uint8_t                     state;
    /* UCT_CXI_UNEXP_{LOST,...} */
    uint8_t                     flags;

    /* The event's match_bits */
    uint64_t                    tag;
    /* iface->tag.unexp_seq of its arrival */
    uint64_t                    seq;
    /* The event's initiator.process */
    uint32_t                    initiator;
    /* Landing of the source address read */
    uint64_t                    value;
    uct_cxi_iface_t             *iface;
    struct uct_cxi_unexp_report *next_free;
    /* iface->tag.unexp_wait while waiting for the announce, else linked to
     * itself */
    ucs_list_link_t             wait;
    /* The first event seen */
    union c_event               event;
} UCS_V_ALIGNED(UCS_SYS_CACHE_LINE_SIZE) uct_cxi_unexp_report_t;

BEGIN_C_DECLS

/* cxi_tag.c: PTE setup */

/*
 * Open the tag PTE and its overflow ring. A no-op (tag.pte stays NULL) without
 * both HW_TM callbacks or with UCX_CXI_TAG_ENABLE=no: UCP then matches in
 * software over AM.
 */
ucs_status_t
uct_cxi_iface_open_tag_pte(uct_cxi_iface_t *self, struct cxil_lni *lni,
                           const uct_cxi_iface_config_t *config,
                           const uct_iface_params_t *params,
                           size_t slot_credits, size_t byte_credits);

void uct_cxi_iface_close_tag_pte(uct_cxi_iface_t *self);

/* Will open_tag_pte offload tag matching for this configuration? */
int uct_cxi_iface_tag_requested(const uct_cxi_iface_config_t *config,
                                const uct_iface_params_t *params);

/* The largest eager tag message (TAG_EAGER_MAX), within what min_free allows */
size_t uct_cxi_tag_max_msg(const uct_cxi_iface_config_t *config);

/*
 * Open the rendezvous source-exposure PTE, whenever tag offload is enabled, at
 * the device's fixed rdzv_get_idx.
 */
ucs_status_t
uct_cxi_iface_open_rdzv_pte(uct_cxi_iface_t *self, struct cxil_lni *lni);

void uct_cxi_iface_close_rdzv_pte(uct_cxi_iface_t *self);

/*
 * cxi_tag.c: event dispatch for the tag PTE, called from the progress loop. The
 * caller splits C_EVENT_PUT by ptl_list: OVERFLOW is an unexpected arrival,
 * PRIORITY a direct match. A direct and a delayed match (C_EVENT_PUT_OVERFLOW)
 * are handled alike, split by event->tgt_long.rendezvous: eager matches
 * complete on this event, rendezvous matches after Put, Rendezvous and Reply
 * (UCT_CXI_RNDV_SEEN_*).
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event);

/*
 * Outcome of one of our SEARCH_AND_DELETE commands. C_EVENT_PUT_OVERFLOW: it
 * deleted the message, nothing left to do. C_EVENT_SEARCH: it found nothing, so
 * a posted receive took a message we gave UCP (an error).
 */
void uct_cxi_iface_tag_handle_search_delete_found(uct_cxi_iface_t *iface,
                                                  const union c_event *event);
void uct_cxi_iface_tag_handle_search_delete_missed(uct_cxi_iface_t *iface,
                                                   const union c_event *event);

/* The C_EVENT_SEARCH of a fence (UCT_CXI_TAG_FENCE_BUFFER_ID) */
void uct_cxi_iface_tag_fence_done(uct_cxi_iface_t *iface,
                                  const union c_event *event);

void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event);
void uct_cxi_iface_tag_handle_rdzv_match(uct_cxi_iface_t *iface,
                                         const union c_event *event);
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                     const union c_event *event);

/*
 * C_EVENT_REPLY of a NIC auto-issued rendezvous Get. A software Get completes
 * through op->handler instead.
 */
void uct_cxi_iface_tag_handle_rdzv_reply(uct_cxi_iface_t *iface,
                                         const union c_event *event);

/* C_EVENT_GET on iface->rdzv.pte: a peer's Get read our exposed LE */
void uct_cxi_iface_tag_handle_rdzv_get(uct_cxi_iface_t *iface,
                                       const union c_event *event);

/* uct_cxi_send_op_t::handler of a rendezvous Put's own ACK */
void uct_cxi_rdzv_put_ack_comp(uct_cxi_send_op_t *op, ucs_status_t status);

/* uct_cxi_send_op_t::handler of a software-issued rendezvous Get's REPLY */
void uct_cxi_rdzv_get_comp(uct_cxi_send_op_t *op, ucs_status_t status);

/*
 * Handler for the announce sent by uct_cxi_ep_send_rndv_hdr_announce(), called
 * from the AM dispatch (UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG).
 */
void uct_cxi_iface_handle_rndv_hdr_announce(uct_cxi_iface_t *iface,
                                            const union c_event *event,
                                            const void *payload, uint32_t len);

/* cxi_tag.c: UCT tag-matching ops, installed into uct_cxi_iface_ops */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length);

ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag, uint64_t imm,
                                   uct_pack_callback_t pack_cb, void *arg,
                                   unsigned flags);

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

ucs_status_ptr_t
uct_cxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag, const void *header,
                          unsigned header_length, const uct_iov_t *iov,
                          size_t iovcnt, unsigned flags,
                          uct_completion_t *comp);

/*
 * A software-only removal: UCT disregards the op without a callback and UCP
 * guarantees it is not completed yet, as in rc_mlx5.
 */
ucs_status_t uct_cxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *op);

ucs_status_t
uct_cxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag, const void *header,
                            unsigned header_length, unsigned flags);

END_C_DECLS

#endif /* UCT_CXI_TAG_H */
