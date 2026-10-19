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

/* Event queue sizing.  UCT_CXI_EQ_NUM_EVENTS is what UCX_CXI_EQ_SIZE's -1
 * sentinel default resolves to — the actual runtime size is
 * uct_cxi_eq_t::num_events, resolved at iface_open together with the
 * TX pool caps (see UCS_CLASS_INIT_FUNC).  UCT_CXI_EQ_ENTRY_SIZE is a
 * hardware constant. */
#define UCT_CXI_EQ_NUM_EVENTS  1024U
#define UCT_CXI_EQ_ENTRY_SIZE  64U   /* sizeof(union c_event) */
/* How long uct_cxi_iface_tgt_post() waits for room in a full target command
 * queue before giving up. The NIC normally frees room within microseconds. */
#define UCT_CXI_TGT_CMDQ_TIMEOUT_SEC  1.0


/* Command queue depth. */
#define UCT_CXI_CMDQ_DEPTH     512U

/* AM receive buffer defaults.  Actual values are runtime-configurable
 * via UCX_CXI_AM_RX_NUM_BUFS and UCX_CXI_AM_RX_BUF_SIZE. */
#define UCT_CXI_AM_RX_BUF_SIZE_DEFAULT  (512u * 1024u)  /* 512 KiB per buffer */
#define UCT_CXI_AM_RX_NUM_BUFS_DEFAULT  4
#define UCT_CXI_AM_RX_NUM_BUFS_MAX      16
/* min_free threshold: max possible message size aligned to 64 B.
 * ceil((sizeof(uint64_t) + C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t) + 63) / 64) * 64
 * = ceil(192/64)*64 = 192; use 256 for a one-slot safety margin. */
#define UCT_CXI_AM_MIN_FREE     256u


/*
 * Number of Logical Address Contexts (LACs) supported per iface.
 *
 * Deliberately fixed at 1 (LAC 0 only) -- not a hardware limit (the NIC
 * supports up to C_NUM_LACS = 8). Only two registration paths can ever
 * produce a driver-assigned LAC != 0: non-dmabuf/raw-P2P GPU memory
 * registration, and huge-page host registration. Both are unsupported;
 * uct_cxi_md_mem_reg() rejects any registration whose LAC isn't 0 with
 * UCS_ERR_UNSUPPORTED, so this is never violated in practice. The
 * supported GPU path (dmabuf-backed, via cuda_copy) always lands on LAC 0.
 *
 * Supporting LAC != 0 is possible but nontrivial: a restricted op's wire
 * packet carries no LAC field at all (verified: cassini_user_defs.h's
 * struct c_port_restricted_hdr has only opcode/index_ext/remote_offset/
 * request_len), so routing would need one PTE per LAC, opened lazily
 * (eagerly opening a PTE for a LAC before any registration under it
 * exists was tried and produced C_RC_INVALID_AC). See the
 * project_cxi_multi_lac_lazy_pte_deferred memory for the full design if
 * this scope needs to expand again.
 *
 * This is a compile-time constant because it controls array sizes in
 * uct_cxi_iface_t and uct_cxi_ep_t; a runtime flag would not shrink them.
 *
 * Portal table entry (PTE) pid_offset assignment:
 *   pid_offsets 0 .. UCT_CXI_MAX_LACS-1  → RMA/AMO, one per LAC
 *   pid_offset  UCT_CXI_MAX_LACS          → Tag-matching (Phase 7)
 *   pid_offset  UCT_CXI_MAX_LACS + 1      → Active messages (Phase 6)
 *   pid_offset  UCT_CXI_MAX_LACS + 2      → Flow-control control channel
 *
 * The rendezvous source-exposure PTE (Phase B) is NOT in this scheme --
 * confirmed on real hardware (every NIC-auto-issued rendezvous Get failed
 * with C_RC_PTLTE_NOT_FOUND) that its pid_idx is a fixed, hardware/driver-
 * mandated value (md->cxi_dev->info.rdzv_get_idx), not something software
 * gets to choose, unlike every PTE above. See uct_cxi_iface_open_rdzv_pte's
 * own comment (cxi_tag.c) and libfabric's matching use of
 * iface->dev->info.rdzv_get_idx (cxip_msg_hpc.c:377, cxip_rdzv_pte.c:290).
 */
#define UCT_CXI_MAX_LACS   1
#define UCT_CXI_PTE_TAG    UCT_CXI_MAX_LACS
#define UCT_CXI_PTE_AM    (UCT_CXI_MAX_LACS + 1)
#define UCT_CXI_PTE_CTRL  (UCT_CXI_MAX_LACS + 2)


/**
 * Node-level address — one per physical NIC.
 * Used by the initiator to route packets to the correct fabric node.
 */
typedef struct uct_cxi_device_addr {
    uint32_t nid; /**< NIC fabric address */
} UCS_S_PACKED uct_cxi_device_addr_t;

/**
 * Per-iface address.
 *
 * Advertises only the PID.  Per-operation pid_offsets (0..UCT_CXI_MAX_LACS-1
 * for RMA, UCT_CXI_PTE_TAG for tag, UCT_CXI_PTE_AM for AM) are protocol
 * constants; the initiator adds them when building the DFA so iface_addr
 * stays compact.
 */
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
    unsigned                 am_rx_num_bufs; /**< # AM receive buffers (PRIORITY MEs) */
    size_t                   am_rx_buf_size; /**< Size of each AM receive buffer     */
    size_t                   am_max_zcopy;  /**< Max AM zcopy payload               */
    unsigned                 eq_size;    /**< RX event queue depth. -1 sentinel
                                              resolves to UCT_CXI_EQ_NUM_EVENTS */
    unsigned                 tx_eq_size; /**< TX event queue depth. -1 sentinel
                                              sizes it from the TX pool caps
                                              (see iface_open)                 */
    unsigned                 eq_max_poll; /**< Max events drained per
                                              iface_progress() call            */
    unsigned                 eq_reserved_slots_pct; /**< % of EQ reserved so RX
                                              traffic can't crowd out TX completions */
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
    unsigned                  tag_ovf_num_bufs; /**< # overflow-ring buffers        */
    size_t                    tag_ovf_buf_size; /**< Size of each overflow buffer   */
    size_t                    tag_eager_max;    /**< Max eager bcopy/zcopy payload;
                                              also sizes the overflow ring
                                              buffers if larger                     */
    unsigned                  tag_max_outstanding; /**< Max simultaneously-posted
                                              priority LEs (hard ceiling 65535 --
                                              buffer_id is uint16_t)                */
#ifndef UCT_CXI_DISABLE_FC
    int                       fc_enable;       /**< Handshake with peers and
                                                    open the control PTE       */
    unsigned                  fc_msg_window;   /**< Message credits granted to
                                                    each peer                  */
    size_t                    fc_byte_window;  /**< Byte credits granted to
                                                    each peer                  */
    double                    fc_connect_timeout; /**< Give up on a peer's
                                                    handshake after this long
                                                    (seconds)                  */
#endif
} uct_cxi_iface_config_t;


/**
 * Per-PTE flow-control recovery state — tracks disable/re-enable flapping
 * so sustained overload escalates (log + stop retrying) instead of spinning
 * SETSTATE commands forever.  One instance per locally-owned PTE (AM, and
 * one per open RMA LAC).
 *
 * `exhausted` tracks matching-resource exhaustion (LE/overflow-list, not
 * EQ capacity) independently of EQ-fill `DRAINING`
 * (uct_cxi_eq_t::need_to_drain) — draining EQ events doesn't free
 * buffer/LE capacity, so the two need separate state.  Only ever set for
 * `iface->am.fc` — never for `iface->rma.fc[]`, since RMA/AMO's catch-all
 * LE is a single persistent non-consuming LE with no matching resource to
 * exhaust (see the design notes in cxi_iface.c's STATE_CHANGE handling).
 * `onload_cb` is a reserved, currently-unused extension point for TAG,
 * which will need an onload step (TGT_SEARCH_AND_DELETE) before repost —
 * reserved now so TAG doesn't need to reshape this struct later.
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

/* TX event queue slots kept out of iface->tx.max_inflight, because the events
 * that use them are not counted in iface->tx.outstanding: the single
 * synchronous get_short's REPLY (1), plus a few for the error events the
 * hardware can report on a command queue's event queue
 * (C_EVENT_COMMAND_FAILURE, C_EVENT_ERROR). Those never occur in normal
 * operation; if more arrive than this holds, the queue drops the extras and
 * progress reports the drop. With flow control, also the control channel's
 * own requests, which are bounded by UCT_CXI_CTRL_SLOTS and bypass the data
 * send cap. Defined here, after cxi_fc.h, so it can name that constant. */
#ifdef UCT_CXI_DISABLE_FC
#define UCT_CXI_TX_EQ_UNTRACKED  8U
#else
/* Plus the control channel's own slots. */
#define UCT_CXI_TX_EQ_UNTRACKED  (8U + UCT_CXI_CTRL_SLOTS)
#endif

/* Defined in cxi_tag.h (included after this header, via cxi_ep.h); only a
 * pointer to it is needed here, so a forward declaration avoids a circular
 * include. */
struct uct_cxi_rdzv_op;

/*
 * Per-peer cache of the two constant-for-the-life-of-the-ep fields of
 * UCP's unexpected-rndv header (ep_id, md_index), populated by that peer's
 * one-time control-message announce (uct_cxi_ep_send_rndv_hdr_announce /
 * uct_cxi_iface_handle_rndv_hdr_announce, cxi_am.c/cxi_tag.c). The header's
 * third field, req_id, varies per message and travels via header_data on
 * every rendezvous Put instead. Growable hash keyed by initiator
 * (event->tgt_long.initiator.initiator.process): the number of distinct
 * peers isn't knowable in advance, and a fixed-size table would either
 * waste memory or, worse, evict a still-needed entry under load -- same
 * reasoning as uct_srd_ep_hash's own per-peer table (uct/ib/efa/srd/
 * srd_iface.h). One entry per peer that has ever sent an announce, for the
 * life of the iface; never removed (a later announce from the same peer
 * just overwrites the existing entry).
 */
typedef struct uct_cxi_rndv_peer_hdr {
    uint64_t ep_id;
    uint8_t  md_index;
} uct_cxi_rndv_peer_hdr_t;
KHASH_MAP_INIT_INT(uct_cxi_rndv_peer_hash, uct_cxi_rndv_peer_hdr_t)

/**
 * Event queue state: the hardware EQ, its backing buffer, and the sizing,
 * drain-gated PTE recovery, and preemptive-growth state that belong to it.
 * The iface owns two (rx_eq, tx_eq), hence a struct rather than loose
 * uct_cxi_iface_t fields.
 */
typedef struct uct_cxi_eq {
    const char    *name;           /**< "rx" / "tx", for log messages */
    struct cxi_eq *evtq;           /**< The hardware event queue */
    void          *buf;            /**< mmap backing buffer for evtq */
    struct cxi_md *md;             /**< cxil_map registration of buf */
    unsigned       num_events;     /**< Runtime EQ depth -- resolved from
                                        UCX_CXI_EQ_SIZE / UCX_CXI_TX_EQ_SIZE
                                        at iface_open; see UCS_CLASS_INIT_FUNC */
    unsigned       max_poll;       /**< Max events drained per
                                        iface_progress() call -- resolved
                                        from UCX_CXI_EQ_MAX_POLL. Bounds
                                        the drain loop the same way every
                                        other UCX transport bounds its
                                        CQ/event poll (RC/UD/DC's
                                        TX/RX_MAX_POLL, TCP's
                                        UCT_TCP_MAX_EVENTS), so a steady
                                        flood can't keep the loop running
                                        past the point where the post-loop
                                        fill-threshold/drop checks would
                                        still have time to act. */

    /* ── PTE flow-control recovery (drain-gated re-enable) ──────────── */
    unsigned       need_to_drain;  /**< >0 while waiting to drain enough of the EQ
                                        before re-checking/re-enabling disabled
                                        PTEs; decremented once per event drained
                                        in iface_progress(), 0 = not recovering */
    unsigned       drain_pct;      /**< Resolved from config at iface_open */
    unsigned       reserved_slots_pct; /**< Resolved from config at iface_open;
                                        persisted (not just applied once)
                                        so eq.grow can recompute the
                                        absolute reserved count as
                                        num_events changes           */
    unsigned       reserved_slots; /**< Current absolute reserved-slot
                                        count, kept in sync with the
                                        value cxil_evtq_adjust_reserved_fc()
                                        reports after each change      */

    /* ── Preemptive EQ growth (fill-threshold-triggered resize) ──────
     * Independent of need_to_drain's reactive drain-and-recover path
     * above — this acts *before* a disable ever happens, on a hardware
     * fill-percentage status update rather than an actual drop/disable
     * event. The two coexist without coupling: DRAINING/EXHAUSTED remain
     * the backstop once eq_max_len is reached or a burst outruns one
     * resize round-trip. See the STATE_CHANGE/EQ_SWITCH handling in
     * cxi_iface.c. */
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

/*
 * Endpoints destroyed with sends still in flight (uct_cxi_ep_destroy): their
 * completions find the ep through a pointer stored in the command, so the ep
 * has to outlive them. The last completion frees it; this set is how the
 * iface finds any that are left when it closes first, since their
 * completions will then never be processed. Keyed by ep address.
 */
KHASH_SET_INIT_INT64(uct_cxi_zombie_ep_hash)

/**
 * CXI interface instance.
 *
 * Hardware resources are grouped into sub-structs by function.  Resources
 * are allocated in a fixed order in UCS_CLASS_INIT_FUNC and must be
 * destroyed in strict reverse order.
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
        unsigned         max_inflight;     /**< Cap on outstanding: every counted
                                                send yields exactly one TX EQ
                                                event, so this is the TX EQ depth
                                                minus UCT_CXI_TX_EQ_UNTRACKED.
                                                Sends beyond it are refused with
                                                UCS_ERR_NO_RESOURCE (-> pending
                                                queue), never queued in the EQ */
        /* Pending-request queue: when a send returns UCS_ERR_NO_RESOURCE,
         * uct_ep_pending_add() queues the caller's callback here via the
         * EP's arb_group.  Drained from uct_cxi_iface_progress() once TX
         * completions free up cmdq/pool resources. */
        ucs_arbiter_t    arbiter;
        /* Short-GET scratch: a page-aligned heap allocation so the NIC's DMA
         * writes land in their own page, away from CPU-hot iface struct
         * fields (prevents false sharing / cache line invalidation).
         * Single-threaded poll model guarantees at most one get_short in
         * flight at a time; the implementation spins until C_EVENT_REPLY
         * and then memcpy's into the caller's buffer. */
        khash_t(uct_cxi_zombie_ep_hash) zombie_eps; /**< Destroyed eps with
                                                          sends in flight   */
        uint8_t              *get_short_buf; /**< Page-aligned, NIC DMA target    */
        uct_cxi_mem_handle_t  get_short_mh;  /**< cxil_map handle for get_short_buf */
    } tx;

    /* ── Shared target-side hardware ────────────────────────────────── */
    struct {
        struct cxi_cq   *cmdq;             /**< Target command queue for LE management */
    } tgt;

    /* ── Event queues; event_type dispatches to the handler ─────────────
     * Two queues share one wait object:
     *  - tx_eq: completions (ACK/REPLY) of commands issued on tx.cmdq. Sized
     *    from the TX pool caps, so it cannot overflow; never grown.
     *  - rx_eq: everything the NIC reports for our own PTEs (incoming
     *    PUT/GET/..., STATE_CHANGE, command-queue events of tgt.cmdq).
     *    Sized by EQ_SIZE; the only queue that can fill from the network,
     *    so the only one with PTE flow-control recovery and growth. */
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
        uint8_t              lac_count;                   /**< # of open RMA PTEs (== UCT_CXI_MAX_LACS once iface_open succeeds) */
        uct_cxi_pte_fc_t      fc[UCT_CXI_MAX_LACS];       /**< Per-LAC recovery state */
    } rma;

    /* ── Tag-matching portal (unrestricted, pid_offset = UCT_CXI_PTE_TAG) ────
     * Real hardware matching (is_matching=1, genuinely exploited here --
     * unlike AM's identically-configured but always-wildcarded PTE).
     * Two independent LE populations share it: on-demand, use_once
     * priority LEs (one per tag_recv_zcopy() call, ctx[]/free_list[]
     * below) bound directly to the caller's own registered buffer for
     * zero-copy direct match, and a genuine Portals4 overflow-list ring
     * (rx_base/rx_mh below) catching unexpected messages -- see cxi_tag.c
     * for why this is a real overflow list, unlike the AM ring. */
    struct {
        struct cxil_pte     *pte;          /**< NULL until HW tag offload enabled */
        struct cxil_pte_map *pte_map;
        int                  enabled;      /**< Opened this run: UCP supplied both
                                                HW_TM callbacks and TAG_ENABLE!=no */

        /* Unexpected-message delivery, registered once at iface_open. */
        uct_tag_unexp_eager_cb_t eager_cb;
        void                     *eager_arg;
        uct_tag_unexp_rndv_cb_t  rndv_cb;
        void                     *rndv_arg;

        /* Outstanding priority-LE tracking -- one slot per posted
         * tag_recv_zcopy() call. buffer_id on the APPEND command is the
         * only correlation field hardware returns (c_target_cmd has no
         * user_ptr, unlike c_full_dma_cmd), so it doubles as the slot
         * index into ctx[]. */
        uct_tag_context_t  **ctx;          /**< [max_outstanding]; NULL = free */
        uint16_t             *free_list;   /**< Stack of free slot indices     */
        unsigned              free_count;  /**< Valid entries in free_list     */
        unsigned              max_outstanding;

        /* Per-slot force-cancel bookkeeping -- deliberately NOT stored in
         * the ctx's own priv (uct_cxi_tag_ctx_priv_t used to have its own
         * cancel_force field there; removed once every reader moved to
         * this array instead, since a field no event handler may ever
         * read again has no reason to keep existing). force=1 means UCP
         * "assumes the cancel is... successful" the
         * instant it calls tag_recv_cancel() (uct.h's own doc comment)
         * and is free to recycle the ucp_request_t ctx/priv live in for a
         * completely different receive before our async C_EVENT_UNLINK
         * confirmation (or a real match landing on the same slot in the
         * meantime) ever arrives -- confirmed on real hardware
         * (cxi_tag.c:1511's own assertion firing with a *different*,
         * live receive's own priv->slot value once UCP reused the
         * memory). Any handler touching a slot must check cancel_ctx[slot]
         * .force first, before dereferencing ctx/priv for anything -- if
         * set, reclaim using only this struct's own fields, never ctx.
         *
         * rndv_seen exists because a force-cancelled *rendezvous* receive
         * can still have up to 3 more real hardware events arrive for its
         * slot (Put/Put_Overflow, Rendezvous, Reply -- see
         * UCT_CXI_RNDV_SEEN_* in cxi_tag.h), all of which must be drained
         * before the slot number is safe to reuse (the underlying LE/pull
         * is still physically in flight in hardware until then --
         * reclaiming the slot number early risks a second, unrelated
         * receive sharing the same buffer_id while the old one's
         * remaining events are still arriving). Since priv->rndv_flags
         * (where this accumulation normally lives) is exactly the unsafe-
         * to-touch memory this struct exists to avoid, tag_recv_cancel()
         * snapshots whatever's accumulated so far into rndv_seen at the
         * moment force-cancel is requested (still safe: read
         * synchronously, before UCP can have reused anything), and every
         * later event for this slot accumulates into it instead of priv
         * from then on. Unused (stays 0) for a plain eager receive. */
        struct {
            uint8_t force;
            uint8_t rndv_seen;
        } *cancel_ctx; /**< [max_outstanding] */

        /* Overflow ring: same shape as am.rx_base/am.rx_mh (contiguous
         * alloc, one registration, buffer_id-indexed, manage_local), real
         * overflow-list semantics (unexpected_hdr_disable=0). Each
         * message's data stays in place until whichever event resolves it
         * (a real priority-LE delayed match, or our own SEARCH_AND_DELETE)
         * -- see ovf_refcnt below for why a buffer generation can't be
         * reposted just because its last arrival set auto_unlinked. */
        uint8_t              *rx_base;
        uct_cxi_mem_handle_t  rx_mh;
        unsigned              num_bufs;
        size_t                buf_size;

        /* Per-buffer-generation reference count -- mirrors libfabric's own
         * cxip_ptelist_buf refcount/consumed design (cxip_ptelist_buf.c).
         * Incremented on a C_EVENT_PUT into this buffer only when
         * mlength>0 -- an mlength==0 arrival has no payload actually
         * sitting in the overflow buffer's memory for anything to read
         * later, so there is nothing to protect and no reference is taken
         * for it at all. Decremented, symmetrically, only by whichever
         * event both resolves that specific message AND actually read its
         * payload (uct_cxi_iface_tag_ovf_release(), called only when that
         * event's own mlength>0 too). A buffer generation's auto_unlinked
         * flag (set on its last arrival) only records that a repost is
         * *pending* (ovf_repost_pending) -- the actual repost is deferred
         * until refcnt drains to 0, so an unresolved earlier message in the
         * same generation can never have its memory reused out from under
         * it.
         *
         * Signed, not unsigned: the event that decrements a given arrival's
         * reference (a real priority-LE delayed match, or our own
         * SEARCH_AND_DELETE outcome) is not guaranteed to be delivered
         * after that same arrival's own raw C_EVENT_PUT -- confirmed on
         * real hardware (a second cluster hit refcnt==0 inside
         * uct_cxi_iface_tag_ovf_release() before that arrival's own
         * increment had run). A decrement can thus transiently land before
         * its matching increment, taking this negative; uct_cxi_iface_tag_
         * ovf_release() and tag_handle_ovf_arrival() both only ever act on
         * the exact value 0 via uct_cxi_iface_tag_ovf_maybe_repost() (never
         * "<= 0"), so this transient state never triggers a premature
         * repost -- it just waits for the out-of-order increment to bring
         * it back to net zero. */
        int32_t              *ovf_refcnt;          /**< [num_bufs] */
        uint8_t              *ovf_repost_pending; /**< [num_bufs] */

        /* uct_cxi_rdzv_get_op_t pool for software-issued (get_issued==0)
         * rendezvous Gets -- see cxi_tag.h. Capped the same as
         * max_outstanding: can never have more outstanding software Gets
         * than outstanding priority-LE receives. */
        ucs_mpool_t           rdzv_get_op_pool;

        /* Per-peer unexpected-rndv header cache -- see uct_cxi_rndv_peer_
         * hdr_t's own doc comment above. Populated by uct_cxi_iface_
         * handle_rndv_hdr_announce() (cxi_tag.c), the receive-side handler
         * for each peer's one-time control-message announce. */
        khash_t(uct_cxi_rndv_peer_hash) rndv_peer_cache;

        /* Genuinely-unexpected rendezvous SEARCH_AND_DELETE confirmations
         * that raced ahead of their initiator's one-time header announce
         * (no ordering guarantee between the two -- see uct_cxi_rndv_unexp_
         * pending_t's own doc comment in cxi_tag.h). Drained by
         * uct_cxi_iface_handle_rndv_hdr_announce() once that initiator's
         * rndv_peer_cache entry is populated. */
        ucs_queue_head_t      rndv_unexp_pending_q;
        ucs_mpool_t           rndv_unexp_pending_pool;

        uct_cxi_pte_fc_t      fc;          /**< Recovery state for tag.pte */
    } tag;

    /* ── Rendezvous source-exposure portal (matching, pid_offset =
     * md->cxi_dev->info.rdzv_get_idx -- a fixed hardware-mandated value,
     * see UCT_CXI_MAX_LACS's own comment above) ──────────────────────
     * Same shape as libfabric's own DEFAULT rendezvous protocol source
     * PTE (cxip_rdzv_match_pte_alloc/cxip_rdzv_pte_src_req_alloc,
     * cxip_rdzv_pte.c): is_matching=1, one persistent whole-LAC-range
     * catch-all LE (match_bits=0/ignore_bits=~0, fully wildcarded -- we
     * have nothing to disambiguate at the matching level itself, being
     * LAC-0-only; matching mode is used here purely to put the resulting
     * Get on the wire format that actually carries match_bits, see
     * uct_ep_tag_rndv_zcopy's own comment). Differs from a genuine
     * matching PTE like TAG/AM only in still being op_get-only, no
     * op_put. LAC 0 only, opened eagerly at iface_open whenever tag
     * offload is enabled (rendezvous has no meaning without it). See
     * cxi_tag.c. */
    struct {
        struct cxil_pte      *pte;        /**< NULL until HW tag offload enabled */
        struct cxil_pte_map  *pte_map;
        int                   enabled;

        /* Outstanding zcopy-exposed sends, one entry per
         * uct_ep_tag_rndv_zcopy() call not yet completed or cancelled.
         * ops[] is a plain fixed-size array (not a pool) indexed by a
         * small dense id that IS the array index -- the arriving
         * C_EVENT_GET's own match_bits carries this id back to us
         * (DEFAULT-protocol style, see uct_ep_tag_rndv_zcopy and
         * uct_cxi_iface_tag_handle_rdzv_get), giving O(1) lookup instead
         * of the address-based linear scan this replaced. Capped at
         * UCT_CXI_RDZV_MAX_OUTSTANDING_MAX (256) -- see cxi_tag.h for
         * why: the id has to survive a hop through the Put's own 8-bit
         * cmd.rendezvous_id field first. */
        struct uct_cxi_rdzv_op *ops;       /**< [max_outstanding] */
        uint32_t              *free_ids;   /**< Stack of free indices into ops[] */
        uint32_t               free_count;
        uint32_t               max_outstanding;

        uct_cxi_pte_fc_t      fc;         /**< Recovery state for rdzv.pte */
    } rdzv;

    /* ── Active-message portal (unrestricted, pid_offset = UCT_CXI_PTE_AM) */
    struct {
        struct cxil_pte      *pte;         /**< Unrestricted AM portal */
        struct cxil_pte_map  *pte_map;
        /* N-buffer rotation on the PRIORITY list.  All buffers are posted
         * at init.  The NIC writes to the head buffer using manage_local=1.
         * When remaining space drops below UCT_CXI_AM_MIN_FREE, the NIC
         * auto-unlinks that buffer and moves to the next.  C_EVENT_UNLINK
         * reposts the consumed buffer at the tail of the list. */
        uint8_t              *rx_base;     /**< Single contiguous allocation */
        uct_cxi_mem_handle_t  rx_mh;       /**< Single cxil_map for rx_base  */
        unsigned              num_bufs;    /**< Runtime buffer count          */
        size_t                buf_size;    /**< Runtime per-buffer size       */
        uint32_t              rx_total;    /**< Total messages received       */
        uct_cxi_pte_fc_t      fc;          /**< Recovery state for am.pte     */
    } am;

#ifndef UCT_CXI_DISABLE_FC
    /* ── Connected-endpoint flow control (peers + control channel) ──── */
    uct_cxi_fc_iface_t    fc;
#endif

    /* ── Domain (VNI + PID) ─────────────────────────────────────────── */
    struct cxil_domain   *domain;

    /* The identity this interface sends as the "initiator" of every
     * unrestricted command (CXI_MATCH_ID of its pid and NIC address). The
     * target's events report the initiator exactly as the sender put it in the
     * command, so a sender that leaves it zero is indistinguishable from every
     * other to the receiver, which keys per-peer state on it (see
     * tag.rndv_peer_cache). Restricted RMA/AMO commands have no such field. */
    uint32_t              match_id;

} uct_cxi_iface_t;


static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_iface_md(uct_cxi_iface_t *iface)
{
    return ucs_derived_of(iface->super.md, uct_cxi_md_t);
}

/*
 * uct_cxi_rc_to_status — map a CXI hardware return code to a ucs_status_t
 * for completion reporting.
 *
 * C_RC_PT_DISABLED maps to UCS_ERR_BUSY rather than a connection/endpoint
 * failure code: the target PTE is in a known, actively-recovering state
 * (en_flowctrl), not a broken connection — UCS_ERR_BUSY's "try again"
 * connotation matches that. Everything else not explicitly handled here
 * maps to the generic UCS_ERR_IO_ERROR.
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

/** Slow path of uct_cxi_iface_tgt_post(); \a ret is the failed emit's result. */
ucs_status_t uct_cxi_iface_tgt_post_wait(uct_cxi_iface_t *iface,
                                         const void *cmd, int ret);

END_C_DECLS

/**
 * Submit a 64-byte target command (struct c_target_cmd or struct
 * c_set_state_cmd) on the target command queue.
 *
 * A full queue is transient -- it only means the NIC has not consumed what
 * was already rung -- so on failure this waits in place until there is room,
 * for at most UCT_CXI_TGT_CMDQ_TIMEOUT_SEC. Callers (event handlers that
 * cannot hand a failure back to anyone) can therefore treat UCS_OK as "the
 * NIC has it". Returns UCS_ERR_TIMED_OUT if the queue stays full for the
 * whole timeout (a wedged NIC), or UCS_ERR_IO_ERROR on any other emit
 * failure.
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

#ifndef UCT_CXI_DISABLE_FC

BEGIN_C_DECLS

/* cxi_peer.c */
ucs_status_t uct_cxi_fc_init(uct_cxi_iface_t *iface,
                             const uct_cxi_iface_config_t *config);
void         uct_cxi_fc_cleanup(uct_cxi_iface_t *iface);
ucs_status_t uct_cxi_iface_open_ctrl_pte(uct_cxi_iface_t *iface,
                                         struct cxil_lni *lni);
void         uct_cxi_iface_close_ctrl_pte(uct_cxi_iface_t *iface);

/**
 * Find or create the peer record for remote interface (\a nid, \a pid).
 * Returns NULL only if memory for the record could not be allocated.
 */
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

/** Resend CREQs that have gone unanswered; give up on stale handshakes. */
void uct_cxi_fc_progress(uct_cxi_iface_t *iface);

END_C_DECLS

#endif /* UCT_CXI_DISABLE_FC */

#endif /* UCT_CXI_IFACE_H */
