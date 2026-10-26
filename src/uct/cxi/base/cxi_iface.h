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

/* Default EQ depth (UCX_CXI_EQ_SIZE=-1) and the hardware event size. */
#define UCT_CXI_EQ_NUM_EVENTS  1024U
#define UCT_CXI_EQ_ENTRY_SIZE  64U   /* sizeof(union c_event) */
/* RX EQ slots, beyond what flow control accounts for, that sizing from the
 * credit windows leaves free: events are acknowledged to the NIC in batches,
 * so processed ones still hold slots for a moment. */
#define UCT_CXI_EQ_SLACK       128U
/* Flow-control credit unit; outside the FC guard since sends compute costs
 * regardless. */
/* Largest windows a CREP can express: 24 bits of slots, 20 bits per class in
 * UCT_CXI_FC_WINDOW_GRAIN units (up to 4 GiB). */
#define UCT_CXI_FC_WINDOW_GRAIN     64u
#define UCT_CXI_FC_MAX_SLOT_WINDOW  ((1u << 24) - 1)
#define UCT_CXI_FC_MAX_UNIT_WINDOW  (((1u << 20) - 1) * UCT_CXI_FC_WINDOW_GRAIN)

#define UCT_CXI_FC_UNIT       64u
#define UCT_CXI_FC_UNITS(_len) \
    ((unsigned)(((_len) + UCT_CXI_FC_UNIT - 1) / UCT_CXI_FC_UNIT))

/* Event slots charged per message: the most events it leaves in the RX EQ at
 * once, besides a posted receive's own (UCT_CXI_TAG_RECV_EVENTS each). An AM
 * leaves its arrival; an eager tag message its arrival, then the search
 * outcome; a rendezvous the search outcome and the source-address read. */
#define UCT_CXI_FC_SLOTS_AM          1u
#define UCT_CXI_FC_SLOTS_TAG_EAGER   1u
#define UCT_CXI_FC_SLOTS_TAG_RNDV    2u
#define UCT_CXI_FC_MAX_SLOTS         UCT_CXI_FC_SLOTS_TAG_RNDV

/** Credit pools: event slots are one pool (the RX EQ is shared), buffer space
 *  one per class (each has its own ring). */
typedef enum {
    UCT_CXI_FC_AM,           /**< Active Messages: the AM ring */
    UCT_CXI_FC_TAG,          /**< tag matching: the overflow ring */
    UCT_CXI_FC_NUM_CLASSES
} uct_cxi_fc_class_t;

/* How long a command posted from an event handler waits for a full command
 * queue. */
#define UCT_CXI_TGT_CMDQ_TIMEOUT_SEC  1.0


/* Command queue depth. */
#define UCT_CXI_CMDQ_DEPTH     512U

/* Control channel: most messages in flight, command queue depth (two commands
 * per message) and default EQ depth (UCX_CXI_CTRL_EQ_SIZE). */
#define UCT_CXI_CTRL_MAX_INFLIGHT   64U
#define UCT_CXI_CTRL_CMDQ_DEPTH     256U
#define UCT_CXI_CTRL_EQ_NUM_EVENTS  256U

/* AM ring: UCX_CXI_AM_RX_BUF_SIZE and _NUM_BUFS are "auto", sized from the
 * credit windows (uct_cxi_iface_size_am_ring) with or without flow control. */
#define UCT_CXI_AM_RX_NUM_BUFS_MAX      64

/* Auto buffer size: a multiple of the largest message, so the stranded tail
 * (min_free) stays small, above a floor that keeps the LE count low. */
#define UCT_CXI_AM_RX_BUF_SIZE_MIN      (1024u * 1024u)
#define UCT_CXI_AM_RX_BUF_PER_MSG       4u

/* min_free is a 24-bit field, and is set to the largest message. */
#define UCT_CXI_AM_MAX_MSG_LIMIT        ((1u << 24) - 1)


/*
 * LACs per iface: fixed at 1. Only non-dmabuf GPU and huge-page host
 * registrations land on another, and uct_cxi_md_mem_reg() rejects them. More
 * would need a lazily opened PTE per LAC (a restricted packet has no LAC
 * field). Compile-time since it sizes arrays.
 *
 * PTE pid_offsets:
 *   0 .. UCT_CXI_MAX_LACS-1   RMA/AMO, one per LAC
 *   UCT_CXI_MAX_LACS          tag matching
 *   UCT_CXI_MAX_LACS + 1      active messages
 *   UCT_CXI_MAX_LACS + 2      flow-control control channel
 * The rendezvous source PTE uses the fixed md->cxi_dev->info.rdzv_get_idx.
 */
#define UCT_CXI_MAX_LACS   1
#define UCT_CXI_PTE_TAG    UCT_CXI_MAX_LACS
#define UCT_CXI_PTE_AM    (UCT_CXI_MAX_LACS + 1)
#define UCT_CXI_PTE_CTRL  (UCT_CXI_MAX_LACS + 2)


/** Node-level address, one per NIC. */
typedef struct uct_cxi_device_addr {
    uint32_t nid; /**< NIC fabric address */
} UCS_S_PACKED uct_cxi_device_addr_t;

/** Per-iface address: the PID. PTE pid_offsets are protocol constants added
 *  when building a DFA. */
typedef struct uct_cxi_iface_addr {
    uint32_t pid; /**< CXI Port ID assigned by cxil_alloc_domain */
} UCS_S_PACKED uct_cxi_iface_addr_t;


/**
 * CXI interface configuration.
 */
typedef struct uct_cxi_iface_config {
    uct_iface_config_t       super;
    uct_iface_mpool_config_t bcopy_mp;  /**< desc_pool config (bufs_grow, max_bufs) */
    uct_iface_mpool_config_t op_mp;     /**< op_pool config (bufs_grow, max_bufs)   */
    size_t                   max_bcopy; /**< Max payload for put_bcopy/get_bcopy    */
    unsigned long            am_rx_num_bufs; /**< # AM receive buffers (PRIORITY MEs),
                                                  or UCS_ULUNITS_AUTO               */
    size_t                   am_rx_buf_size; /**< Size of each AM receive buffer, or
                                                  UCS_MEMUNITS_AUTO                 */
    size_t                   am_max_zcopy;  /**< Max AM zcopy header + payload      */
    unsigned                 eq_size;    /**< RX event queue depth. -1 sentinel
                                              resolves to UCT_CXI_EQ_NUM_EVENTS */
    unsigned                 tx_eq_size; /**< TX event queue depth. -1 sentinel
                                              sizes it from the TX pool caps
                                              (see iface_open)                 */
    unsigned                 eq_max_poll; /**< Max events drained per
                                              iface_progress() call            */
    unsigned                 eq_reserved_slots; /**< RX EQ slots kept for events
                                              that are not incoming messages  */
    unsigned                 eq_drain_pct;   /**< % of EQ to drain (from the point a
                                              drop is detected) before attempting to
                                              re-enable a disabled PTE               */
    unsigned                 eq_flap_limit;  /**< Max disable/re-enable cycles for one
                                              PTE within eq_flap_window before giving
                                              up on it                              */
    double                    eq_flap_window; /**< Time window for eq_flap_limit,
                                              seconds (UCS_CONFIG_TYPE_TIME)        */
    int                       dynamic_eq_growth; /**< Grow the RX EQ preemptively on a
                                              hardware fill-threshold crossing,
                                              instead of waiting to hit it        */
    unsigned                  eq_grow_thresh_pct; /**< Fill % that triggers a resize */
    unsigned                  eq_max_len;     /**< Ceiling on uct_cxi_eq_t::num_events growth,
                                              in events (same unit as eq_size)      */
    ucs_ternary_auto_value_t  tag_enable;     /**< Force-disable HW tag offload
                                              even if UCP requests it (UCS_NO) --
                                              falls back to SW tag matching over AM */
    unsigned long             tag_ovf_num_bufs; /**< # overflow-ring buffers, or
                                              UCS_ULUNITS_AUTO                      */
    size_t                    tag_ovf_buf_size; /**< Size of each overflow buffer, or
                                              UCS_MEMUNITS_AUTO                     */
    size_t                    tag_eager_max;    /**< Max eager tag message */
    unsigned                  tag_max_outstanding; /**< Max simultaneously-posted
                                              priority LEs (hard ceiling 65535 --
                                              buffer_id is uint16_t)                */
    unsigned                  tag_fence_interval; /**< Posted receives between
                                              fences (see uct_cxi_tag_pend_t)       */
    unsigned                  fc_msg_window;   /**< Event slots granted per
                                                    peer */
    size_t                    fc_byte_window;  /**< Active Message buffer
                                                    credits granted to each
                                                    peer                       */
    size_t                    fc_tag_byte_window; /**< Tag matching buffer
                                                    credits granted to each
                                                    peer                       */
    unsigned                  fc_active_senders; /**< Peers at full window at
                                                      once */
#ifndef UCT_CXI_DISABLE_FC
    unsigned                  ctrl_eq_size;    /**< Control EQ depth, -1:
                                                    default */
    int                       fc_enable;       /**< Handshake with peers and
                                                    open the control PTE       */
    double                    fc_connect_timeout; /**< Give up on a peer's
                                                    handshake after this long
                                                    (seconds)                  */
    double                    fc_grant_thresh; /**< Send a pure credit grant once
                                                    this fraction of a window is
                                                    owed to a peer             */
#endif
} uct_cxi_iface_config_t;


/**
 * Per-PTE recovery state: flap counting, so sustained overload gives up
 * instead of re-enabling forever. One per PTE that arms flow control (AM, tag,
 * rendezvous). `exhausted` marks matching-resource exhaustion (AM only),
 * apart from EQ-fill draining since draining frees no buffers.
 */
typedef struct uct_cxi_pte_fc {
    ucs_time_t flap_window_start; /**< Start of the current flap-counting window */
    unsigned   flap_count;        /**< Disable events observed within the window */
    int        gave_up;           /**< Stopped attempting re-enable for this PTE */
    int        exhausted;         /**< Matching-resource exhaustion (AM/TAG only) */
    void      *onload_cb;         /**< Reserved for TAG; unused today */
} uct_cxi_pte_fc_t;


#ifndef UCT_CXI_DISABLE_FC
#include "cxi_fc.h"
#endif

/* TX EQ slots kept out of tx.max_inflight for events not counted in
 * tx.outstanding: the get_short REPLY and a few hardware error events (extra
 * ones are dropped and reported by progress). */
#define UCT_CXI_TX_EQ_UNTRACKED  8U

/* Defined in cxi_tag.h (included after this header, via cxi_ep.h); only a
 * pointer to it is needed here, so a forward declaration avoids a circular
 * include. */
struct uct_cxi_rdzv_op;

/*
 * Per-peer cache of the constant {ep_id, md_index} fields of UCP's unexpected
 * rendezvous header, filled by the peer's one-time announce. A hash keyed by
 * initiator, one entry per peer for the life of the iface.
 */
typedef struct uct_cxi_rndv_peer_hdr {
    uint64_t ep_id;
    uint64_t table_iova; /**< IOVA of the sender's rendezvous address table
                              (rdzv.addr_table): slot i holds the source
                              address of its rendezvous with id i */
    uint8_t  md_index;
} uct_cxi_rndv_peer_hdr_t;
KHASH_MAP_INIT_INT(uct_cxi_rndv_peer_hash, uct_cxi_rndv_peer_hdr_t)

/**
 * An unexpected eager message that a posted receive takes: its overflow-list
 * arrival and the receive's delayed match are separate events, in either order,
 * so the first waits for the other (iface->tag.eager_pairs, keyed by the
 * message's address in the overflow buffer).
 */
typedef struct uct_cxi_eager_pair {
    uint64_t      seq;       /**< when the arrival was handled, in the numbering
                                  of tag.unexp_seq (set by the arrival) */
    uint8_t       parked;    /**< 0: the arrival was seen and waits for its
                                  match; 1: a match was seen and waits for
                                  its arrival, and is kept in `event` */
    union c_event event;
} uct_cxi_eager_pair_t;
KHASH_MAP_INIT_INT64(uct_cxi_eager_pair_hash, uct_cxi_eager_pair_t)

/**
 * Unexpected messages held for the report to UCP from one sender with one tag,
 * in arrival order (uct_cxi_unexp_report_t); found by (sender, tag) in
 * iface->tag.unexp_streams while any are held.
 */
typedef struct uct_cxi_unexp_stream {
    ucs_list_link_t              live;      /**< iface->tag.unexp_live, while in
                                                 use (has an entry) */
    ucs_list_link_t              entries;   /**< uct_cxi_unexp_report_t.link */
    uint64_t                     tag;
    uint32_t                     initiator;
    unsigned                     num_lost;  /**< entries in the chain that are
                                                 tombstones (UCT_CXI_UNEXP_LOST) */
    int                          busy;      /**< being advanced */
    struct uct_cxi_unexp_stream *next_free;
} uct_cxi_unexp_stream_t;

/*
 * A posted receive that may still take a message from the overflow list.
 * Hardware reports such a match only afterwards (the delayed match), so
 * receives are kept in posting order in iface->tag.pend: an unexpected message
 * goes to the first PENDING one whose tag matches (uct_cxi_tag_claim), which
 * becomes CLAIMED, and is SPENT once its outcome is known.
 *
 * A fence (uct_cxi_tag_fence_post: a search matching nothing, every
 * TAG_FENCE_INTERVAL receives) bounds the ring: when its event arrives, every
 * receive before it has been appended and reported, and leaves the ring.
 */
typedef struct uct_cxi_tag_pend {
    uint64_t tag;
    uint64_t mask;
    uint16_t slot;
    uint8_t  state;
} uct_cxi_tag_pend_t;

#define UCT_CXI_TAG_PEND_FREE    0  /* not a receive (never in the window) */
#define UCT_CXI_TAG_PEND_PENDING 1
#define UCT_CXI_TAG_PEND_CLAIMED 2
#define UCT_CXI_TAG_PEND_SPENT   3

typedef struct uct_cxi_unexp_key {
    uint64_t tag;
    uint32_t initiator;
} uct_cxi_unexp_key_t;

#define uct_cxi_unexp_key_hash(_k) \
    kh_int64_hash_func((_k).tag ^ ((uint64_t)(_k).initiator * \
                                   0x9e3779b97f4a7c15ull))
#define uct_cxi_unexp_key_equal(_a, _b) \
    (((_a).tag == (_b).tag) && ((_a).initiator == (_b).initiator))
KHASH_INIT(uct_cxi_unexp_stream_hash, uct_cxi_unexp_key_t,
           uct_cxi_unexp_stream_t *, 1, uct_cxi_unexp_key_hash,
           uct_cxi_unexp_key_equal)

/** An event queue: the hardware EQ and its buffer, with its sizing, PTE
 *  recovery and growth state. */
typedef struct uct_cxi_eq {
    const char    *name;           /**< "rx" / "tx", for log messages */
    struct cxi_eq *evtq;           /**< The hardware event queue */
    void          *buf;            /**< mmap backing buffer for evtq */
    struct cxi_md *md;             /**< cxil_map registration of buf */
    unsigned       num_events;     /**< Runtime EQ depth -- resolved from
                                        UCX_CXI_EQ_SIZE / UCX_CXI_TX_EQ_SIZE
                                        at iface_open; see UCS_CLASS_INIT_FUNC */
    unsigned       max_poll;       /**< Max events drained per progress
                                         call (UCX_CXI_EQ_MAX_POLL) */

    /* ── PTE flow-control recovery (drain-gated re-enable) ──────────── */
    unsigned       need_to_drain;  /**< >0 while draining before PTEs are
                                         re-enabled; one per event processed */
    unsigned       drain_pct;      /**< Resolved from config at iface_open */
    unsigned       reserved_slots_cfg; /**< Resolved from config at iface_open;
                                        persisted so eq.grow can restore it
                                        if the resize changes the count */
    unsigned       reserved_slots; /**< Current reserved slots, as reported by
                                         cxil_evtq_adjust_reserved_fc() */

    /* Preemptive growth: a hardware fill-threshold update triggers a resize
     * before any disable; reactive recovery stays the backstop. */
    struct {
        int            enabled;        /**< Resolved from dynamic_eq_growth */
        unsigned       thresh_pct;     /**< Resolved from eq_grow_thresh_pct */
        unsigned       max_len_events; /**< Resolved from eq_max_len        */
        int            resizing;       /**< true from cxil_evtq_resize() to
                                            cxil_evtq_resize_complete()    */
        void          *pending_buf;    /**< New (larger) buffer awaiting
                                            C_EVENT_EQ_SWITCH              */
        struct cxi_md *pending_md;     /**< cxil_map registration of
                                            pending_buf                   */
        size_t         pending_len;    /**< Byte length of pending_buf     */
    } grow;
} uct_cxi_eq_t;

#ifndef UCT_CXI_DISABLE_FC
/**
 * The control channel (cxi_ctrl.c): its own PTE, event queue (arrivals and send
 * completions, whose slots are reserved) and command queue.
 */
typedef struct uct_cxi_ctrl {
    int                   enabled;      /**< Opened (FC_ENABLE) */
    uct_cxi_eq_t          eq;
    struct cxi_cq         *cmdq;         /**< Where control messages are sent */
    struct cxil_pte      *pte;
    struct cxil_pte_map  *pte_map;
    ucs_mpool_t           req_pool;     /**< uct_cxi_ctrl_req_t */
    unsigned              outstanding;  /**< Control messages in flight */
    unsigned              max_inflight; /**< Cap on outstanding; one reserved EQ
                                              slot per message */
} uct_cxi_ctrl_t;
#endif

/*
 * Endpoints destroyed with sends in flight: the last completion frees each, and
 * the iface frees any left at close. Keyed by ep address.
 */
KHASH_SET_INIT_INT64(uct_cxi_zombie_ep_hash)

/**
 * CXI interface instance. Resources are allocated in UCS_CLASS_INIT_FUNC order
 * and destroyed in reverse.
 */
typedef struct uct_cxi_iface {
    uct_base_iface_t  super;               /**< Must be first */

    /* ── Shared initiator-side TX hardware ──────────────────────────── */
    struct {
        struct cxi_cq   *cmdq;             /**< TX command queue (CXI_CQ_IS_TX) */
        struct cxi_cp   *cp;               /**< Communication profile / TC */
        ucs_mpool_t      op_pool;          /**< uct_cxi_send_op_t — zcopy/short ops */
        ucs_mpool_t      desc_pool;        /**< uct_cxi_send_desc_t — bcopy bounce bufs */
        size_t           max_bcopy;        /**< Max payload per bcopy op (from config) */
        unsigned         outstanding;      /**< Total in-flight sends (all EPs) */
#ifndef UCT_CXI_DISABLE_FC
        uint8_t          credit_block;     /**< Set by a send refused for
                                                lack of credits (not an
                                                interface resource), for the
                                                pending dispatch to read */
#endif
        unsigned         max_inflight;     /**< Cap on outstanding: TX EQ
                                                depth minus
                                                UCT_CXI_TX_EQ_UNTRACKED.
                                                Beyond it sends get
                                                UCS_ERR_NO_RESOURCE. */
        /* Pending sends: uct_ep_pending_add() queues them on the ep's
         * arb_group; progress runs them. */
        ucs_arbiter_t    arbiter;
        /* get_short scratch, page-aligned to keep NIC writes off hot iface
         * fields. */
        khash_t(uct_cxi_zombie_ep_hash) zombie_eps; /**< Destroyed eps with
                                                          sends in flight   */
        uint8_t              *get_short_buf; /**< Page-aligned, NIC DMA target    */
        uct_cxi_mem_handle_t  get_short_mh;  /**< cxil_map handle for get_short_buf */
    } tx;

    /* ── Shared target-side hardware ────────────────────────────────── */
    struct {
        struct cxi_cq   *cmdq;             /**< Target command queue for LE management */
    } tgt;

    /* ── Event queues ──
     *  - tx_eq: ACK/REPLY of commands on tx.cmdq; sized from the TX pool caps.
     *  - rx_eq: everything for our PTEs; the only queue the network can fill,
     *    so the only one with recovery and growth. */
    struct cxil_wait_obj *wait_obj;        /**< Interrupt / epoll fd for progress */
    uct_cxi_eq_t          rx_eq;
    uct_cxi_eq_t          tx_eq;

    /* ── PTE flow-control recovery (drain-gated re-enable) ──────────── */
    unsigned   eq_flap_limit;    /**< Resolved from config at iface_open */
    ucs_time_t eq_flap_window;   /**< Resolved from config at iface_open */

    /* ── RMA/AMO portals (restricted, pid_offset = LAC index) ───────── */
    struct {
        struct cxil_pte     *pte[UCT_CXI_MAX_LACS];     /**< One PTE per LAC, all opened eagerly at iface_open */
        struct cxil_pte_map *pte_map[UCT_CXI_MAX_LACS];
    } rma;

    /* ── Tag-matching portal (pid_offset = UCT_CXI_PTE_TAG) ──
     * Hardware matching with two LE populations: use_once priority LEs, one per
     * tag_recv_zcopy() bound to the caller's buffer, and an overflow-list ring
     * catching unexpected messages. */
    struct {
        struct cxil_pte     *pte;          /**< NULL until HW tag offload enabled */
        int32_t              ptn;          /**< pte->ptn, or -1 if no PTE;
                                                compared with an event's
                                                ptlte_index */
        struct c_target_cmd  recv_le;      /**< The priority LE every posted
                                                receive is, but for buffer
                                                and tag */
        struct cxil_pte_map *pte_map;
        int                  enabled;      /**< Opened this run: UCP supplied both
                                                HW_TM callbacks and TAG_ENABLE!=no */

        /* Unexpected-message delivery, registered once at iface_open. */
        uct_tag_unexp_eager_cb_t eager_cb;
        void                     *eager_arg;
        uct_tag_unexp_rndv_cb_t  rndv_cb;
        void                     *rndv_arg;

        /* One slot per posted tag_recv_zcopy(); the APPEND's buffer_id (the
         * only field hardware returns) indexes ctx[]. */
        uct_tag_context_t  **ctx;          /**< [max_outstanding]; NULL = free */
        uint16_t             *free_list;   /**< Stack of free slot indices     */
        unsigned              free_count;  /**< Valid entries in free_list     */
        unsigned              max_outstanding;

        /* Per-slot force-cancel state, kept out of the ctx's priv: after a
         * forced cancel UCP may reuse that memory before our UNLINK arrives, so
         * handlers check cancel_ctx[slot].force before touching ctx. rndv_seen
         * snapshots the rendezvous events seen at cancel time (up to 3 more may
         * arrive, UCT_CXI_RNDV_SEEN_*); all must drain before the slot is
         * reused. Stays 0 for an eager receive. */
        struct {
            uint8_t force;
            uint8_t rndv_seen;
        } *cancel_ctx; /**< [max_outstanding] */

        /* Overflow ring, shaped like am.rx_base with overflow-list semantics. A
         * message stays in place until its resolving event (a delayed match or
         * our SEARCH_AND_DELETE); see ovf_refcnt. */
        uint8_t              *rx_base;
        uct_cxi_mem_handle_t  rx_mh;
        unsigned              num_bufs;
        size_t                buf_size;
        size_t                unexp_max;   /**< Unexpected messages held at
                                                once (entries, streams): what
                                                the credits allow with flow
                                                control */
        size_t                max_msg;     /**< Largest eager message:
                                                advertised, and the LEs'
                                                min_free so one always fits */

        /* Per-buffer-generation reference count (as libfabric's
         * cxip_ptelist_buf). Taken on a PUT with mlength > 0, dropped by the
         * event that resolves the message after reading its payload
         * (uct_cxi_iface_tag_ovf_release). auto_unlinked only marks a repost
         * pending; it happens at zero. Signed: the resolving event can arrive
         * before the PUT's own increment, so it may go transiently negative;
         * reposting acts on exactly 0 only. */
        int32_t              *ovf_refcnt;          /**< [num_bufs] */
        uint8_t              *ovf_repost_pending; /**< [num_bufs] */

        /* Pool of software-issued rendezvous Gets, capped like
         * max_outstanding. */
        ucs_mpool_t           rdzv_get_op_pool;

        /* Per-peer unexpected-rndv header cache, filled by
         * uct_cxi_iface_handle_rndv_hdr_announce(). */
        khash_t(uct_cxi_rndv_peer_hash) rndv_peer_cache;

        /* Unexpected eager messages with data that have had one of their
         * two events, see uct_cxi_eager_pair_t. */
        khash_t(uct_cxi_eager_pair_hash) eager_pairs;

        /* Unexpected messages held for the report to UCP
         * (uct_cxi_unexp_report_t): unexp_ents is a registered array (also each
         * address read's landing buffer) with free list unexp_free, chained per
         * (sender, tag) in unexp_streams (storage unexp_stream_pool, free list
         * unexp_stream_free). unexp_wait holds rendezvous whose sender's
         * announce is not seen yet; unexp_held counts rendezvous entries, so
         * the eager path looks for a stream only when it is not 0. */
        khash_t(uct_cxi_unexp_stream_hash) unexp_streams;
        uct_cxi_unexp_stream_t *unexp_stream_pool;
        uct_cxi_unexp_stream_t *unexp_stream_free;
        ucs_list_link_t       unexp_wait;
        ucs_list_link_t       unexp_live;       /**< the streams in use, to tell
                                                     whether a receive would
                                                     match one (recv_zcopy) */
        struct uct_cxi_unexp_report *unexp_ents;
        struct uct_cxi_unexp_report *unexp_free;
        uct_cxi_mem_handle_t  unexp_ents_mh;
        size_t                unexp_ents_len;   /**< registered bytes */
        unsigned              unexp_held;
        uint64_t              unexp_seq;        /**< numbers the unexpected arrivals
                                                     as they are handled: the
                                                     order of a stream's chain */

        /* Receives that may take an unexpected message (uct_cxi_tag_pend_t).
         * pend_head and pend_tail count up and wrap (index modulo
         * UCT_CXI_TAG_PEND_SIZE); slot_pos[slot] is a receive's count; fences[]
         * holds the pend_head each in-flight fence covers. */
        uct_cxi_tag_pend_t   *pend;        /**< [UCT_CXI_TAG_PEND_SIZE] */
        uint32_t             *slot_pos;    /**< [max_outstanding] */
        uint32_t             *fences;      /**< [UCT_CXI_TAG_PEND_SIZE] */
        uint32_t              pend_head;
        uint32_t              pend_tail;
        uint32_t              fence_head;
        uint32_t              fence_tail;
        unsigned              fence_interval; /**< receives between fences */
        unsigned              fence_posts;    /**< posted since the last one */

        uct_cxi_pte_fc_t      fc;          /**< Recovery state for tag.pte */
    } tag;

    /* ── Rendezvous source-exposure portal (pid_offset = rdzv_get_idx, fixed by
     * hardware) ──
     * As libfabric's default rendezvous source PTE: matching, one wildcard LE
     * over the whole range, op_get only; matching mode only puts the Get on
     * the wire format that carries match_bits. LAC 0, opened when tag offload
     * is enabled (cxi_tag.c). */
    struct {
        struct cxil_pte      *pte;        /**< NULL until HW tag offload enabled */
        int32_t               ptn;        /**< pte->ptn, or -1 if no PTE;
                                               compared with an event's
                                               ptlte_index */
        struct cxil_pte_map  *pte_map;
        int                   enabled;

        /* Outstanding rndv sends (uct_ep_tag_rndv_zcopy) by a dense id that the
         * C_EVENT_GET match_bits carries back. At most
         * UCT_CXI_RDZV_MAX_OUTSTANDING_MAX: the id passes through an 8-bit
         * field. */
        struct uct_cxi_rdzv_op *ops;       /**< [max_outstanding] */
        uint32_t              *free_ids;   /**< Stack of free indices into ops[] */
        uint32_t               free_count;
        uint32_t               max_outstanding;

        /* addr_table[id]: IOVA of the buffer rendezvous id exposes, registered
         * so a peer can read it with an RMA Get (base sent in the ep's
         * announce); the hardware gives a target no source address for an
         * unexpected rendezvous. Written before the Put; all 256 ids, so a read
         * stays inside. */
        uint64_t              *addr_table;
        uct_cxi_mem_handle_t   addr_table_mh;
        size_t                 addr_table_len;   /**< registered bytes */

        uct_cxi_pte_fc_t      fc;         /**< Recovery state for rdzv.pte */
    } rdzv;

    /* ── Active-message portal (unrestricted, pid_offset = UCT_CXI_PTE_AM) */
    struct {
        struct cxil_pte      *pte;         /**< Unrestricted AM portal */
        struct cxil_pte_map  *pte_map;
        /* PRIORITY-list ring of manage_local buffers, all posted at init. A
         * buffer unlinks itself when less than max_msg is left, flagging the
         * Put that did it (auto_unlinked), which reposts it at the tail. A Put
         * that does not fit the linked buffer fails with NO_SPACE. */
        uint8_t              *rx_base;     /**< Single contiguous allocation */
        uct_cxi_mem_handle_t  rx_mh;       /**< Single cxil_map for rx_base  */
        unsigned              num_bufs;    /**< Runtime buffer count          */
        size_t                buf_size;    /**< Runtime per-buffer size       */
        size_t                max_zcopy;   /**< Largest am_zcopy header +
                                                payload (AM_MAX_ZCOPY)        */
        size_t                max_msg;     /**< Largest message that can land
                                                in a buffer: the greater of
                                                max_zcopy and max_bcopy      */
        uint32_t              rx_total;    /**< Total messages received       */
        uct_cxi_pte_fc_t      fc;          /**< Recovery state for am.pte     */
    } am;

#ifndef UCT_CXI_DISABLE_FC
    /* ── Connected-endpoint flow control (peers + control channel) ──── */
    uct_cxi_fc_iface_t    fc;
    uct_cxi_ctrl_t        ctrl;
#endif

    /* ── Domain (VNI + PID) ─────────────────────────────────────────── */
    struct cxil_domain   *domain;

    /* The "initiator" of every unrestricted command; targets key per-peer state
     * on it (tag.rndv_peer_cache). Restricted RMA/AMO commands have none. */
    uint32_t              match_id;

} uct_cxi_iface_t;


static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_iface_md(uct_cxi_iface_t *iface)
{
    return ucs_derived_of(iface->super.md, uct_cxi_md_t);
}

/*
 * Map a hardware return code to a status: PT_DISABLED is UCS_ERR_BUSY (the
 * target is recovering, "try again"); anything unlisted UCS_ERR_IO_ERROR.
 */
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

/** Slow path of uct_cxi_iface_tgt_post(); \a ret is the failed emit's result. */
ucs_status_t uct_cxi_iface_tgt_post_wait(uct_cxi_iface_t *iface,
                                         const void *cmd, int ret);

END_C_DECLS

/**
 * A command could not be emitted (\a ret): -ENOSPC is an ordinary shortage and
 * silent; anything else is logged.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_tx_emit_error(const void *obj, const char *what, int ret)
{
    if (ucs_unlikely(ret != -ENOSPC)) {
        uct_cxi_tx_emit_failed(obj, what, ret);
    }
}

/**
 * Submit a 64-byte target command. A full queue is transient, so this waits up
 * to UCT_CXI_TGT_CMDQ_TIMEOUT_SEC; event handlers can treat UCS_OK as "the NIC
 * has it". UCS_ERR_TIMED_OUT if still full, else UCS_ERR_IO_ERROR.
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

UCS_CLASS_DECLARE(uct_cxi_iface_t, uct_md_h, uct_worker_h,
                  const uct_iface_params_t*, const uct_iface_config_t*)

ucs_status_t uct_cxi_iface_query(uct_iface_h tl_iface,
                                  uct_iface_attr_t *iface_attr);


ucs_status_t uct_cxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                  uct_completion_t *comp);
ucs_status_t uct_cxi_iface_get_device_address(uct_iface_h tl_iface,
                                               uct_device_addr_t *dev_addr);
ucs_status_t uct_cxi_iface_get_address(uct_iface_h tl_iface,
                                        uct_iface_addr_t *iface_addr);
int uct_cxi_iface_is_reachable(uct_iface_h tl_iface,
                                const uct_device_addr_t *dev_addr,
                                const uct_iface_addr_t *iface_addr);
int uct_cxi_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                   const uct_iface_is_reachable_params_t *params);
ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p);

BEGIN_C_DECLS

/* cxi_eq.c */
void         uct_cxi_eq_configure(uct_cxi_eq_t *eq, const char *name,
                                  unsigned num_events, unsigned reserved_slots,
                                  int grow_enabled,
                                  const uct_cxi_iface_config_t *config);
ucs_status_t uct_cxi_eq_init(uct_cxi_eq_t *eq, struct cxil_lni *lni,
                             struct cxil_wait_obj *wait_obj);
void         uct_cxi_eq_cleanup(uct_cxi_eq_t *eq);
void         uct_cxi_eq_abort_resize(uct_cxi_eq_t *eq);
void         uct_cxi_iface_eq_grow_start(uct_cxi_iface_t *iface,
                                         uct_cxi_eq_t *eq);
void         uct_cxi_iface_eq_grow_complete(uct_cxi_iface_t *iface,
                                            uct_cxi_eq_t *eq);

/* cxi_iface.c */
void         uct_cxi_fc_windows(const uct_cxi_iface_config_t *config,
                                size_t am_max_msg, size_t tag_max_msg,
                                uint32_t *slot_window_p,
                                uint32_t unit_window[UCT_CXI_FC_NUM_CLASSES]);

END_C_DECLS

#ifndef UCT_CXI_DISABLE_FC

BEGIN_C_DECLS

/* cxi_peer.c */
ucs_status_t uct_cxi_fc_init(uct_cxi_iface_t *iface,
                             const uct_cxi_iface_config_t *config,
                             uint32_t slot_window,
                             const uint32_t unit_window[UCT_CXI_FC_NUM_CLASSES]);
void         uct_cxi_fc_cleanup(uct_cxi_iface_t *iface);

/* cxi_ctrl.c */
ucs_status_t uct_cxi_ctrl_open(uct_cxi_iface_t *iface,
                               const uct_cxi_iface_config_t *config,
                               struct cxil_lni *lni);
void         uct_cxi_ctrl_close(uct_cxi_iface_t *iface);

/**
 * Send a control message to \a peer; UCS_ERR_NO_RESOURCE if the channel is
 * full. \a grant_slots and \a grant_units are what a GRANT carries.
 */
ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                               unsigned type, uint64_t match_bits,
                               uint64_t header_data, uint32_t grant_slots,
                               const uint32_t *grant_units);

/* cxi_peer.c */

/** Find or create the record of remote iface (\a nid, \a pid); NULL on no
 *  memory. */
uct_cxi_peer_t *uct_cxi_peer_get(uct_cxi_iface_t *iface, uint32_t nid,
                                 uint32_t pid);

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

/** The peer record for event initiator \a process, or NULL if there is none
 *  (a sender without flow control). Refills the one-entry cache. */
uct_cxi_peer_t *uct_cxi_fc_rx_peer_slow(uct_cxi_iface_t *iface,
                                        uint32_t process);

/** Credits piggybacked on an Active Message from \a peer (\a match_bits). */
void uct_cxi_fc_apply_piggyback(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                                uint64_t match_bits);

/** We owe \a peer a lot of credits: send it a GRANT now, or when we can. */
void uct_cxi_fc_grant_wanted(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Make runnable the endpoints of \a peer that were waiting for credits. */
void uct_cxi_peer_resume(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Take back credits the target will never return: the send was lost, or the
 *  target does not track it (a tag message that matched a posted receive). */
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

/** Forget that we told \a peer anything we cannot be sure it received. */
void uct_cxi_fc_resync(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer);

/** Park \a ep, whose pending queue waits for credits, on its peer. */
void uct_cxi_fc_block_ep(struct uct_cxi_ep *ep);

/** Forget \a ep (being destroyed) wherever it is parked. */
void uct_cxi_fc_unblock_ep(struct uct_cxi_ep *ep);

END_C_DECLS

/** The record of the sender of the AM just received, or NULL (no flow control:
 *  not charged). */
static UCS_F_ALWAYS_INLINE uct_cxi_peer_t *
uct_cxi_fc_rx_peer(uct_cxi_iface_t *iface, uint32_t process)
{
    if (ucs_likely((iface->fc.rx_cache_peer != NULL) &&
                   (iface->fc.rx_cache_key == process))) {
        return iface->fc.rx_cache_peer;
    }

    return uct_cxi_fc_rx_peer_slow(iface, process);
}

/** A message of \a cls and \a mlength bytes from \a peer, charged \a slots, was
 *  processed: its credits are ours to return. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_fc_rx_done(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                   unsigned cls, unsigned slots, uint32_t mlength)
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

#endif /* UCT_CXI_DISABLE_FC */

#endif /* UCT_CXI_IFACE_H */
