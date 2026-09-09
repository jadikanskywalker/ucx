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
#include <ucs/datastruct/mpool.h>
#include <ucs/time/time.h>

#include <libcxi/libcxi.h>


#define UCT_CXI_NAME "cxi"

/* Event queue sizing.  UCT_CXI_EQ_NUM_EVENTS is what UCX_CXI_EQ_SIZE's -1
 * sentinel default resolves to — the actual runtime size is
 * uct_cxi_iface_t::eq_num_events, resolved at iface_open together with the
 * TX pool caps (see UCS_CLASS_INIT_FUNC).  UCT_CXI_EQ_ENTRY_SIZE is a
 * hardware constant. */
#define UCT_CXI_EQ_NUM_EVENTS  1024U
#define UCT_CXI_EQ_ENTRY_SIZE  64U   /* sizeof(union c_event) */

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
 */
#define UCT_CXI_MAX_LACS   1
#define UCT_CXI_PTE_TAG    UCT_CXI_MAX_LACS
#define UCT_CXI_PTE_AM    (UCT_CXI_MAX_LACS + 1)
#define UCT_CXI_PTE_COUNT (UCT_CXI_MAX_LACS + 2)


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
    unsigned                 eq_size;    /**< Event queue depth. -1 sentinel
                                              resolves to UCT_CXI_EQ_NUM_EVENTS;
                                              pool caps derive from whichever
                                              this resolves to (see iface_open) */
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
    int                       dynamic_eq_growth; /**< Grow the EQ preemptively on a
                                              hardware fill-threshold crossing,
                                              instead of waiting to hit it        */
    unsigned                  eq_grow_thresh_pct; /**< Fill % that triggers a resize */
    unsigned                  eq_max_len;     /**< Ceiling on eq_num_events growth,
                                              in events (same unit as eq_size)      */
    ucs_ternary_auto_value_t  tag_enable;     /**< Force-disable HW tag offload
                                              even if UCP requests it (UCS_NO) --
                                              falls back to SW tag matching over AM */
    unsigned                  tag_ovf_num_bufs; /**< # overflow-ring buffers        */
    size_t                    tag_ovf_buf_size; /**< Size of each overflow buffer   */
    size_t                    tag_eager_max;    /**< Max eager bcopy/zcopy payload;
                                              also sizes unexp_pool elements and the
                                              overflow ring buffers if larger       */
    unsigned                  tag_max_outstanding; /**< Max simultaneously-posted
                                              priority LEs (hard ceiling 65535 --
                                              buffer_id is uint16_t)                */
    unsigned                  tag_unexp_max_bufs; /**< Cap on the unexpected-message
                                              copy-out pool                        */
} uct_cxi_iface_config_t;


/**
 * Per-PTE flow-control recovery state — tracks disable/re-enable flapping
 * so sustained overload escalates (log + stop retrying) instead of spinning
 * SETSTATE commands forever.  One instance per locally-owned PTE (AM, and
 * one per open RMA LAC).
 *
 * `exhausted` tracks matching-resource exhaustion (LE/overflow-list, not
 * EQ capacity) independently of EQ-fill `DRAINING`
 * (uct_cxi_iface_t::eq_need_to_drain) — draining EQ events doesn't free
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
        uint8_t              *get_short_buf; /**< Page-aligned, NIC DMA target    */
        uct_cxi_mem_handle_t  get_short_mh;  /**< cxil_map handle for get_short_buf */
    } tx;

    /* ── Shared target-side hardware ────────────────────────────────── */
    struct {
        struct cxi_cq   *cmdq;             /**< Target command queue for LE management */
    } tgt;

    /* ── Event queue (single EQ; event_type dispatches to handler) ─── */
    struct cxil_wait_obj *wait_obj;        /**< Interrupt / epoll fd for progress */
    void                 *eq_buf;          /**< mmap backing buffer for evtq */
    struct cxi_md        *eq_md;           /**< cxil_map registration of eq_buf */
    struct cxi_eq        *evtq;            /**< Event queue (shared by all CMDQs & PTEs) */
    unsigned              eq_num_events;   /**< Runtime EQ depth — resolved from
                                                UCX_CXI_EQ_SIZE and TX pool caps at
                                                iface_open; see UCS_CLASS_INIT_FUNC */
    unsigned              eq_max_poll;     /**< Max events drained per
                                                iface_progress() call — resolved
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
    unsigned   eq_need_to_drain; /**< >0 while waiting to drain enough of the EQ
                                      before re-checking/re-enabling disabled
                                      PTEs; decremented once per event drained
                                      in iface_progress(), 0 = not recovering */
    unsigned   eq_drain_pct;     /**< Resolved from config at iface_open */
    unsigned   eq_flap_limit;    /**< Resolved from config at iface_open */
    ucs_time_t eq_flap_window;   /**< Resolved from config at iface_open */
    unsigned   eq_reserved_slots_pct; /**< Resolved from config at iface_open;
                                           persisted (not just applied once)
                                           so eq_grow can recompute the
                                           absolute reserved count as
                                           eq_num_events changes           */
    unsigned   eq_reserved_slots;     /**< Current absolute reserved-slot
                                           count, kept in sync with the
                                           value cxil_evtq_adjust_reserved_fc()
                                           reports after each change      */

    /* ── Preemptive EQ growth (fill-threshold-triggered resize) ──────
     * Independent of eq_need_to_drain's reactive drain-and-recover path
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
    } eq_grow;

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

        /* Overflow ring: same shape as am.rx_base/am.rx_mh (contiguous
         * alloc, one registration, buffer_id-indexed, manage_local), but
         * real overflow-list semantics (unexpected_hdr_disable=0). Data
         * is copied out and handed to eager_cb/rndv_cb immediately and
         * unconditionally -- never retained waiting for a future post. */
        uint8_t              *rx_base;
        uct_cxi_mem_handle_t  rx_mh;
        unsigned              num_bufs;
        size_t                buf_size;

        ucs_mpool_t           unexp_pool;  /**< Copy-out buffers for unexpected
                                                messages handed to eager_cb/rndv_cb */

        uct_cxi_pte_fc_t      fc;          /**< Recovery state for tag.pte */
    } tag;

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

    /* ── Domain (VNI + PID) ─────────────────────────────────────────── */
    struct cxil_domain   *domain;

} uct_cxi_iface_t;


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

#endif /* UCT_CXI_IFACE_H */
