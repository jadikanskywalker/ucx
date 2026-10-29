/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI interface definitions.
 */

#ifndef UCT_CXI_IFACE_H
#define UCT_CXI_IFACE_H

#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/api/uct.h>
#include <ucs/datastruct/arbiter.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/datastruct/queue.h>
#include <ucs/time/time.h>

#include <libcxi/libcxi.h>
#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>


#define UCT_CXI_NAME "cxi"

typedef struct uct_cxi_iface uct_cxi_iface_t;

/* Largest CREP windows: 24 bits of slots, 20 bits per class in
 * UCT_CXI_FC_WINDOW_GRAIN units. */
#define UCT_CXI_FC_WINDOW_GRAIN    64u
#define UCT_CXI_FC_MAX_SLOT_WINDOW ((1u << 24) - 1)
#define UCT_CXI_FC_MAX_UNIT_WINDOW (((1u << 20) - 1) * UCT_CXI_FC_WINDOW_GRAIN)

/* Credit unit; outside the FC guard because sends compute costs regardless. */
#define UCT_CXI_FC_UNIT 64u
#define UCT_CXI_FC_UNITS(_len) \
    ((unsigned)(((_len) + UCT_CXI_FC_UNIT - 1) / UCT_CXI_FC_UNIT))

/* Event slots a message holds in the RX EQ at once, besides a posted receive's
 * own (UCT_CXI_TAG_RECV_EVENTS). */
#define UCT_CXI_FC_SLOTS_AM        1u
#define UCT_CXI_FC_SLOTS_TAG_EAGER 1u
#define UCT_CXI_FC_SLOTS_TAG_RNDV  2u
#define UCT_CXI_FC_MAX_SLOTS       UCT_CXI_FC_SLOTS_TAG_RNDV

/** Credit pools: event slots (the shared RX EQ), then buffer space per class,
 *  each with its own ring. */
typedef enum {
    /* AM ring */
    UCT_CXI_FC_AM,
    /* Tag overflow ring */
    UCT_CXI_FC_TAG,
    UCT_CXI_FC_NUM_CLASSES
} uct_cxi_fc_class_t;

/* Wait for a full command queue when posting from an event handler. */
#define UCT_CXI_TGT_CMDQ_TIMEOUT_SEC 1.0

/* Wait for a PTE's STATE_CHANGE after enabling it. */
#define UCT_CXI_PTE_ENABLE_TIMEOUT_SEC 5.0


/* Command queue depth. */
#define UCT_CXI_CMDQ_DEPTH 512U


/* AM ring, auto-sized from the credit windows (uct_cxi_iface_size_am_ring). */
#define UCT_CXI_AM_RX_NUM_BUFS_MAX 64

/* Auto buffer size: a multiple of the largest message, above a floor. */
#define UCT_CXI_AM_RX_BUF_SIZE_MIN (1024u * 1024u)
#define UCT_CXI_AM_RX_BUF_PER_MSG  4u

/* min_free is a 24-bit field, and is set to the largest message. */
#define UCT_CXI_AM_MAX_MSG_LIMIT ((1u << 24) - 1)


/*
 * LACs per iface: 1, since only non-dmabuf GPU and huge-page host
 * registrations land on another and uct_cxi_md_mem_reg() rejects them.
 *
 * PTE pid_offsets:
 *   0 .. UCT_CXI_MAX_LACS-1   RMA/AMO, one per LAC
 *   UCT_CXI_MAX_LACS          tag matching
 *   UCT_CXI_MAX_LACS + 1      active messages
 *   UCT_CXI_MAX_LACS + 2      flow-control control channel
 * The rendezvous source PTE uses the fixed md->cxi_dev->info.rdzv_get_idx.
 */
#define UCT_CXI_MAX_LACS 1
#define UCT_CXI_PTE_TAG  UCT_CXI_MAX_LACS
#define UCT_CXI_PTE_AM   (UCT_CXI_MAX_LACS + 1)
#define UCT_CXI_PTE_CTRL (UCT_CXI_MAX_LACS + 2)


/** Node-level address, one per NIC. */
typedef struct uct_cxi_device_addr {
    /* NIC fabric address */
    uint32_t nid;
} UCS_S_PACKED uct_cxi_device_addr_t;

/** Per-iface address: the PID. */
typedef struct uct_cxi_iface_addr {
    /* CXI Port ID assigned by cxil_alloc_domain */
    uint32_t pid;
} UCS_S_PACKED uct_cxi_iface_addr_t;


/**
 * CXI interface configuration.
 */
typedef struct uct_cxi_iface_config {
    uct_iface_config_t       super;
    /* desc_pool config */
    uct_iface_mpool_config_t bcopy_mp;
    /* op_pool config */
    uct_iface_mpool_config_t op_mp;
    /* Max put/get bcopy payload */
    size_t                   max_bcopy;
    /* AM receive buffers, or UCS_ULUNITS_AUTO */
    unsigned long            am_rx_num_bufs;
    /* Size of each AM receive buffer, or UCS_MEMUNITS_AUTO */
    size_t                   am_rx_buf_size;
    /* Max AM zcopy header + payload */
    size_t                   am_max_zcopy;
    /* RX EQ depth; -1: UCT_CXI_EQ_NUM_EVENTS */
    unsigned                 eq_size;
    /* TX EQ depth; -1: sized from the TX pool caps */
    unsigned                 tx_eq_size;
    /* Max events drained per progress call */
    unsigned                 eq_max_poll;
    /* RX EQ slots kept for events that are not messages */
    unsigned                 eq_reserved_slots;
    /* Percentage of the EQ drained after a drop before re-enabling the PTE */
    unsigned                 eq_drain_pct;
    /* Max disable/re-enable cycles per PTE within eq_flap_window */
    unsigned                 eq_flap_limit;
    /* In seconds */
    double                   eq_flap_window;
    /* Grow the RX EQ on a hardware fill threshold, before a drop */
    int                      dynamic_eq_growth;
    /* Fill percentage that triggers a resize */
    unsigned                 eq_grow_thresh_pct;
    /* Ceiling on EQ growth, in events */
    unsigned                 eq_max_len;
    /* UCS_NO: software tag matching over AM */
    ucs_ternary_auto_value_t tag_enable;
    /* Overflow-ring buffers, or UCS_ULUNITS_AUTO */
    unsigned long            tag_ovf_num_bufs;
    /* Overflow buffer size, or UCS_MEMUNITS_AUTO */
    size_t                   tag_ovf_buf_size;
    /* Max eager tag message */
    size_t                   tag_eager_max;
    /* Max posted receives (at most 65535: buffer_id is uint16_t) */
    unsigned                 tag_max_outstanding;
    /* Receives between fences */
    unsigned                 tag_fence_interval;
    /* Event slots granted per peer */
    unsigned                 fc_msg_window;
    /* AM buffer credits granted per peer */
    size_t                   fc_byte_window;
    /* Tag buffer credits granted per peer */
    size_t                   fc_tag_byte_window;
    /* Peers at full window at once */
    unsigned                 fc_active_senders;
#ifndef UCT_CXI_DISABLE_FC
    /* Control EQ depth; -1: default */
    unsigned ctrl_eq_size;
    /* Handshake with peers and open the control PTE */
    int fc_enable;
    /* Seconds before giving up on a handshake */
    double fc_connect_timeout;
    /* Fraction of a window owed before a pure GRANT is sent */
    double fc_grant_thresh;
#endif
} uct_cxi_iface_config_t;


/**
 * Per-PTE recovery state (AM, tag, rendezvous): flap counting, so sustained
 * overload gives up instead of re-enabling forever.
 */
typedef struct uct_cxi_pte_fc {
    /* Start of the flap window */
    ucs_time_t flap_window_start;
    /* Disables within the window */
    unsigned   flap_count;
    /* Stopped re-enabling this PTE */
    int        gave_up;
    /* Matching resources exhausted (AM/TAG only) */
    int        exhausted;
} uct_cxi_pte_fc_t;


#include "cxi_eq.h"

#ifndef UCT_CXI_DISABLE_FC
#include "cxi_fc.h"
#include "cxi_ctrl.h"
#endif

/* TX EQ slots kept out of tx.max_inflight for events not in tx.outstanding
 * (the get_short REPLY, hardware errors). */
#define UCT_CXI_TX_EQ_UNTRACKED 8U

/* Defined in cxi_tag.h; forward declared to avoid a circular include. */
struct uct_cxi_rdzv_op;

/* Per-peer cache of UCP's constant unexpected-rndv header fields, keyed by
 * initiator and filled by the peer's announce. */
typedef struct uct_cxi_rndv_peer_hdr {
    uint64_t ep_id;
    /* IOVA of the sender's rdzv.addr_table */
    uint64_t table_iova;
    uint8_t  md_index;
} uct_cxi_rndv_peer_hdr_t;
KHASH_MAP_INIT_INT(uct_cxi_rndv_peer_hash, uct_cxi_rndv_peer_hdr_t)

/**
 * An unexpected eager message that a posted receive takes: its arrival and the
 * receive's delayed match come in either order, so the first waits for the
 * other (tag.eager_pairs, keyed by the message's overflow-buffer address).
 */
typedef struct uct_cxi_eager_pair {
    /* Arrival order, from tag.unexp_seq */
    uint64_t      seq;
    /* 0: the arrival waits for its match; 1: the match, kept in event, waits
     * for its arrival */
    uint8_t       parked;
    union c_event event;
} uct_cxi_eager_pair_t;
KHASH_MAP_INIT_INT64(uct_cxi_eager_pair_hash, uct_cxi_eager_pair_t)

/** Unexpected messages held for the report to UCP from one sender with one
 *  tag, in arrival order. */
typedef struct uct_cxi_unexp_stream {
    /* Link in tag.unexp_live while in use */
    ucs_list_link_t             live;
    /* uct_cxi_unexp_report_t.link */
    ucs_list_link_t             entries;
    uint64_t                    tag;
    uint32_t                    initiator;
    /* Tombstones (UCT_CXI_UNEXP_LOST) in the chain */
    unsigned                    num_lost;
    /* Being advanced */
    int                         busy;
    struct uct_cxi_unexp_stream *next_free;
} uct_cxi_unexp_stream_t;

/*
 * A posted receive that may still take an overflow-list message, kept in
 * posting order in tag.pend. An unexpected message goes to the first PENDING
 * receive whose tag matches (uct_cxi_tag_claim), which becomes CLAIMED, then
 * SPENT once its outcome is known. A fence (uct_cxi_tag_fence_post) bounds the
 * ring: receives before it have been reported and leave it.
 */
typedef struct uct_cxi_tag_pend {
    uint64_t tag;
    uint64_t mask;
    uint16_t slot;
    uint8_t  state;
} uct_cxi_tag_pend_t;

/* Not a receive */
#define UCT_CXI_TAG_PEND_FREE    0
#define UCT_CXI_TAG_PEND_PENDING 1
#define UCT_CXI_TAG_PEND_CLAIMED 2
#define UCT_CXI_TAG_PEND_SPENT   3

typedef struct uct_cxi_unexp_key {
    uint64_t tag;
    uint32_t initiator;
} uct_cxi_unexp_key_t;

#define uct_cxi_unexp_key_hash(_k) \
    kh_int64_hash_func((_k).tag ^ \
                       ((uint64_t)(_k).initiator * 0x9e3779b97f4a7c15ull))
#define uct_cxi_unexp_key_equal(_a, _b) \
    (((_a).tag == (_b).tag) && ((_a).initiator == (_b).initiator))
KHASH_INIT(uct_cxi_unexp_stream_hash, uct_cxi_unexp_key_t,
           uct_cxi_unexp_stream_t*, 1, uct_cxi_unexp_key_hash,
           uct_cxi_unexp_key_equal)


/* Endpoints destroyed with sends in flight, keyed by address: the last
 * completion frees each, the iface frees any left at close. */
KHASH_SET_INIT_INT64(uct_cxi_zombie_ep_hash)

/**
 * CXI interface instance. Resources are allocated in UCS_CLASS_INIT_FUNC order
 * and destroyed in reverse.
 */
struct uct_cxi_iface {
    /* Must be first */
    uct_base_iface_t super;

    /* Shared initiator-side TX hardware */
    struct {
        struct cxi_cq *cmdq;
        /* Communication profile / TC */
        struct cxi_cp *cp;
        /* uct_cxi_send_op_t (zcopy, short) and uct_cxi_send_desc_t (bcopy) */
        ucs_mpool_t   op_pool;
        ucs_mpool_t   desc_pool;
        size_t        max_bcopy;
        /* In-flight sends, all EPs */
        unsigned      outstanding;
#ifndef UCT_CXI_DISABLE_FC
        /* Set by a send refused for lack of credits, for the pending dispatch
         * to read */
        uint8_t credit_block;
#endif
        /* Cap on outstanding: TX EQ depth minus UCT_CXI_TX_EQ_UNTRACKED */
        unsigned max_inflight;
        /* Pending sends queued on the eps' arb_groups; progress runs them */
        ucs_arbiter_t arbiter;
        khash_t(uct_cxi_zombie_ep_hash) zombie_eps;
        /* get_short DMA target, page-aligned to keep NIC writes off hot iface
         * fields */
        uint8_t *get_short_buf;
        uct_cxi_mem_handle_t get_short_mh;
    } tx;

    /* Shared target-side command queue for LE management */
    struct {
        struct cxi_cq *cmdq;
    } tgt;

    /* tx_eq holds the ACK/REPLY of tx.cmdq commands; rx_eq everything for our
     * PTEs, the only queue the network can fill and so the only one with
     * recovery and growth. */
    struct cxil_wait_obj *wait_obj;
    uct_cxi_eq_t rx_eq;
    uct_cxi_eq_t tx_eq;

    /* Resolved from config */
    unsigned eq_flap_limit;
    ucs_time_t eq_flap_window;

    /* RMA/AMO portals (restricted, pid_offset = LAC index) */
    struct {
        struct cxil_pte     *pte[UCT_CXI_MAX_LACS];
        struct cxil_pte_map *pte_map[UCT_CXI_MAX_LACS];
    } rma;

    /* Tag-matching portal (pid_offset = UCT_CXI_PTE_TAG): use_once priority
     * LEs, one per tag_recv_zcopy(), and an overflow-list ring catching
     * unexpected messages. */
    struct {
        /* NULL until HW tag offload is enabled */
        struct cxil_pte          *pte;
        /* pte->ptn, or -1; compared with an event's ptlte_index */
        int32_t                  ptn;
        /* The priority LE every posted receive is, but for buffer and tag */
        struct c_target_cmd      recv_le;
        struct cxil_pte_map      *pte_map;
        /* UCP supplied both HW_TM callbacks and TAG_ENABLE != no */
        int                      enabled;

        /* Unexpected-message delivery, registered at iface_open */
        uct_tag_unexp_eager_cb_t eager_cb;
        void                     *eager_arg;
        uct_tag_unexp_rndv_cb_t  rndv_cb;
        void                     *rndv_arg;

        /* Posted receives by slot: the APPEND's buffer_id indexes ctx[]
         * [max_outstanding]; NULL = free */
        uct_tag_context_t        **ctx;
        /* Stack of free slots */
        uint16_t                 *free_list;
        unsigned                 free_count;
        unsigned                 max_outstanding;

        /* Per-slot force-cancel state, outside the ctx that UCP may reuse
         * before our UNLINK arrives. rndv_seen snapshots the rendezvous events
         * seen at cancel time, all of which must drain before the slot is
         * reused. [max_outstanding] */
        struct {
            uint8_t force;
            uint8_t rndv_seen;
        } * cancel_ctx;

        /* Overflow ring, like am.rx_base: a message stays in place until its
         * resolving event (a delayed match or our SEARCH_AND_DELETE) */
        uint8_t                            *rx_base;
        uct_cxi_mem_handle_t               rx_mh;
        unsigned                           num_bufs;
        size_t                             buf_size;
        /* Unexpected messages held at once */
        size_t                             unexp_max;
        /* Largest eager message, also the LEs' min_free */
        size_t                             max_msg;

        /* Per-buffer reference counts [num_bufs]: taken on a PUT with data,
         * dropped by the event that resolves the message
         * (uct_cxi_iface_tag_ovf_release). Signed since the resolving event can
         * precede the PUT's increment; a repost acts on exactly 0. */
        int32_t                            *ovf_refcnt;
        uint8_t                            *ovf_repost_pending;

        /* Software-issued rendezvous Gets, capped like max_outstanding */
        ucs_mpool_t                        rdzv_get_op_pool;

        /* Filled by uct_cxi_iface_handle_rndv_hdr_announce() */
        khash_t(uct_cxi_rndv_peer_hash)    rndv_peer_cache;

        /* Unexpected eager messages that have had one of their two events */
        khash_t(uct_cxi_eager_pair_hash)   eager_pairs;

        /* Unexpected messages held for the report to UCP: unexp_ents is a
         * registered array (also the landing buffer of address reads) with
         * free list unexp_free, chained per (sender, tag) in unexp_streams.
         * unexp_wait holds rendezvous whose sender's announce is not seen yet;
         * unexp_held counts rendezvous entries. */
        khash_t(uct_cxi_unexp_stream_hash) unexp_streams;
        uct_cxi_unexp_stream_t             *unexp_stream_pool;
        uct_cxi_unexp_stream_t             *unexp_stream_free;
        ucs_list_link_t                    unexp_wait;
        /* Streams in use */
        ucs_list_link_t                    unexp_live;
        struct uct_cxi_unexp_report        *unexp_ents;
        struct uct_cxi_unexp_report        *unexp_free;
        uct_cxi_mem_handle_t               unexp_ents_mh;
        size_t                             unexp_ents_len;
        unsigned                           unexp_held;
        /* Numbers the unexpected arrivals in handling order */
        uint64_t                           unexp_seq;

        /* Receives that may take an unexpected message. pend_head/pend_tail
         * count up and wrap (modulo UCT_CXI_TAG_PEND_SIZE); slot_pos[slot] is
         * a receive's count; fences[] holds the pend_head each in-flight fence
         * covers. */
        uct_cxi_tag_pend_t                 *pend;
        /* [max_outstanding] */
        uint32_t                           *slot_pos;
        uint32_t                           *fences;
        uint32_t                           pend_head;
        uint32_t                           pend_tail;
        uint32_t                           fence_head;
        uint32_t                           fence_tail;
        /* Receives between fences, and posted since the last one */
        unsigned                           fence_interval;
        unsigned                           fence_posts;

        uct_cxi_pte_fc_t                   fc;
    } tag;

    /* Rendezvous source-exposure portal (pid_offset = rdzv_get_idx, fixed by
     * hardware), as libfabric's: one wildcard LE, op_get only. Matching mode
     * puts the Get on the wire format that carries match_bits. LAC 0, opened
     * with tag offload (cxi_tag.c). */
    struct {
        /* NULL until HW tag offload is enabled */
        struct cxil_pte        *pte;
        /* pte->ptn, or -1; compared with an event's ptlte_index */
        int32_t                ptn;
        struct cxil_pte_map    *pte_map;
        int                    enabled;

        /* Outstanding rndv sends by a dense id that the C_EVENT_GET
         * match_bits carry back, at most UCT_CXI_RDZV_MAX_OUTSTANDING_MAX
         * (the id is 8 bits). [max_outstanding] */
        struct uct_cxi_rdzv_op *ops;
        /* Stack of free indices into ops[] */
        uint32_t               *free_ids;
        uint32_t               free_count;
        uint32_t               max_outstanding;

        /* addr_table[id]: IOVA of the buffer rendezvous id exposes, for a
         * peer's RMA Get (the hardware gives a target no source address for an
         * unexpected rendezvous). All 256 ids, so a read stays inside. */
        uint64_t               *addr_table;
        uct_cxi_mem_handle_t   addr_table_mh;
        size_t                 addr_table_len;

        uct_cxi_pte_fc_t       fc;
    } rdzv;

    /* Active-message portal (unrestricted, pid_offset = UCT_CXI_PTE_AM) */
    struct {
        struct cxil_pte      *pte;
        struct cxil_pte_map  *pte_map;
        /* PRIORITY-list ring of manage_local buffers, posted at init. A buffer
         * unlinks itself when less than max_msg is left, flagging the Put that
         * did it (auto_unlinked), which reposts it at the tail. A Put that does
         * not fit the linked buffer fails with NO_SPACE. */
        uint8_t              *rx_base;
        uct_cxi_mem_handle_t rx_mh;
        unsigned             num_bufs;
        size_t               buf_size;
        size_t               max_zcopy;
        /* Largest message that can land in a buffer: max(max_zcopy,
         * max_bcopy) */
        size_t               max_msg;
        uct_cxi_pte_fc_t     fc;
    } am;

#ifndef UCT_CXI_DISABLE_FC
    /* Connected-endpoint flow control: peers and control channel */
    uct_cxi_fc_iface_t fc;
    uct_cxi_ctrl_t ctrl;
#endif

    struct cxil_domain *domain;

    /* The "initiator" of every unrestricted command; targets key per-peer state
     * on it (tag.rndv_peer_cache). Restricted RMA/AMO commands have none. */
    uint32_t match_id;
};


static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_iface_md(uct_cxi_iface_t *iface)
{
    return ucs_derived_of(iface->super.md, uct_cxi_md_t);
}

/* PT_DISABLED (the target is recovering) is UCS_ERR_BUSY, other errors are
 * UCS_ERR_IO_ERROR. */
static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_rc_to_status(int rc)
{
    switch (rc) {
    case C_RC_OK:
        return UCS_OK;
    case C_RC_PT_DISABLED:
        return UCS_ERR_BUSY;
    default:
        return UCS_ERR_IO_ERROR;
    }
}


BEGIN_C_DECLS

/** Slow path of uct_cxi_tx_emit_error(). */
void uct_cxi_tx_emit_failed(const void *obj, const char *what, int ret);

/** Slow path of uct_cxi_iface_tgt_post(); \a ret is the emit's result. */
ucs_status_t
uct_cxi_iface_tgt_post_wait(uct_cxi_iface_t *iface, const void *cmd, int ret);

/** Pool ops for objects only software reads: the NIC never DMAs into them. */
extern ucs_mpool_ops_t uct_cxi_host_mpool_ops;

/** Enable \a pte and wait for its STATE_CHANGE on \a eq; fails on a timeout. */
ucs_status_t uct_cxi_iface_pte_enable(uct_cxi_iface_t *iface,
                                      struct cxil_pte *pte, uct_cxi_eq_t *eq);

/* cxi_iface.c */
ucs_status_t
uct_cxi_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr);
ucs_status_t uct_cxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp);
ucs_status_t uct_cxi_iface_get_device_address(uct_iface_h tl_iface,
                                              uct_device_addr_t *dev_addr);
ucs_status_t
uct_cxi_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *iface_addr);
int uct_cxi_iface_is_reachable(uct_iface_h tl_iface,
                               const uct_device_addr_t *dev_addr,
                               const uct_iface_addr_t *iface_addr);
int uct_cxi_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                  const uct_iface_is_reachable_params_t *params);
ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p);

END_C_DECLS

/** A command could not be emitted: -ENOSPC is an ordinary shortage, silent. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_tx_emit_error(const void *obj, const char *what, int ret)
{
    if (ucs_unlikely(ret != -ENOSPC)) {
        uct_cxi_tx_emit_failed(obj, what, ret);
    }
}

/**
 * Submit a 64-byte target command, waiting up to UCT_CXI_TGT_CMDQ_TIMEOUT_SEC
 * for a full queue; UCS_OK means the NIC has it.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_iface_tgt_post(uct_cxi_iface_t *iface, const void *cmd)
{
    int ret = cxi_cq_emit_target(iface->tgt.cmdq, cmd);

    if (ucs_likely(ret == 0)) {
        cxi_cq_ring(iface->tgt.cmdq);
        return UCS_OK;
    }

    return uct_cxi_iface_tgt_post_wait(iface, cmd, ret);
}

/**
 * Fill what the AM and tag overflow ring LEs share: Put-only, the NIC advances
 * start per message (manage_local, with the relaxed ordering it requires), no
 * link or unlink events since the last PUT carries auto_unlinked, and oversized
 * messages are rejected rather than truncated.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_ring_le_init(struct c_target_cmd *le, const struct cxil_pte *pte,
                     enum c_ptl_list ptl_list, int buf_idx, int restart_seq)
{
    le->command.opcode       = C_CMD_TGT_APPEND;
    le->ptl_list             = ptl_list;
    le->ptlte_index          = pte->ptn;
    le->op_put               = 1;
    le->manage_local         = 1;
    le->unrestricted_body_ro = 1;
    le->unrestricted_end_ro  = 1;
    le->event_link_disable   = 1;
    le->event_unlink_disable = 1;
    le->no_truncate          = 1;
    le->restart_seq          = restart_seq;
    le->match_id             = CXI_MATCH_ID_ANY;
    le->buffer_id            = (uint16_t)buf_idx;
    le->ignore_bits          = UINT64_MAX;
}

UCS_CLASS_DECLARE(uct_cxi_iface_t, uct_md_h, uct_worker_h,
                  const uct_iface_params_t*, const uct_iface_config_t*)

#ifndef UCT_CXI_DISABLE_FC
#include "cxi_peer.h"
#endif

#endif /* UCT_CXI_IFACE_H */
