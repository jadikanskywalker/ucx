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
#include <ucs/datastruct/mpool.h>

#include <libcxi/libcxi.h>


#define UCT_CXI_NAME "cxi"

/* Event queue sizing. */
#define UCT_CXI_EQ_NUM_EVENTS  1024U
#define UCT_CXI_EQ_ENTRY_SIZE  64U   /* sizeof(union c_event) */
#define UCT_CXI_EQ_BUF_LEN    (UCT_CXI_EQ_NUM_EVENTS * UCT_CXI_EQ_ENTRY_SIZE)

/* Command queue depth. */
#define UCT_CXI_CMDQ_DEPTH     256U

/* AM receive buffers: two 512 KiB OVERFLOW LEs (ping-pong).
 * When the active buffer fills to within UCT_CXI_AM_MIN_FREE bytes, the NIC
 * auto-unlinks it (sets auto_unlinked=1 in the final C_EVENT_PUT) and we post
 * the spare buffer.  This prevents data races without requiring handler-level
 * acknowledgement.  Messages may be dropped if both buffers are simultaneously
 * full, but in-progress data is never corrupted. */
#define UCT_CXI_AM_RX_BUF_SIZE  (512u * 1024u)  /* 512 KiB per buffer */
#define UCT_CXI_AM_RX_NUM_BUFS  2
/* min_free threshold: max possible message size aligned to 64 B.
 * ceil((sizeof(uint64_t) + C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t) + 63) / 64) * 64
 * = ceil(192/64)*64 = 192; use 256 for a one-slot safety margin. */
#define UCT_CXI_AM_MIN_FREE     256u


/*
 * Number of Logical Address Contexts (LACs) supported per iface.
 *
 * Default (1): only LAC 0 is used; standard 4 KiB-page registrations always
 * land in LAC 0.  Build with --enable-huge-pages (sets UCT_CXI_ENABLE_HUGE_PAGES)
 * to support LACs 1-7 for huge-page registrations.
 *
 * This is a compile-time constant because it controls array sizes in
 * uct_cxi_iface_t and uct_cxi_ep_t; a runtime flag would not shrink them.
 *
 * Portal table entry (PTE) pid_offset assignment:
 *   pid_offsets 0 .. UCT_CXI_MAX_LACS-1  → RMA/AMO, one per LAC
 *   pid_offset  UCT_CXI_MAX_LACS          → Tag-matching (Phase 7)
 *   pid_offset  UCT_CXI_MAX_LACS + 1      → Active messages (Phase 6)
 */
#ifdef UCT_CXI_ENABLE_HUGE_PAGES
#  define UCT_CXI_MAX_LACS   8
#else
#  define UCT_CXI_MAX_LACS   1
#endif
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
    size_t                   max_bcopy; /**< Max payload for put_bcopy/get_bcopy    */
} uct_cxi_iface_config_t;


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

    /* ── RMA/AMO portals (restricted, pid_offset = LAC index) ───────── */
    struct {
        struct cxil_pte     *pte[UCT_CXI_MAX_LACS];     /**< NULL until LAC used */
        struct cxil_pte_map *pte_map[UCT_CXI_MAX_LACS];
        uint8_t              lac_count;                   /**< # of open RMA PTEs */
    } rma;

    /* ── Tag-matching portal (unrestricted, pid_offset = UCT_CXI_PTE_TAG) — Phase 7 */
    struct {
        struct cxil_pte     *pte;          /**< NULL until tag ops enabled */
        struct cxil_pte_map *pte_map;
    } tag;

    /* ── Active-message portal (unrestricted, pid_offset = UCT_CXI_PTE_AM) */
    struct {
        struct cxil_pte      *pte;         /**< Unrestricted AM portal */
        struct cxil_pte_map  *pte_map;
        /* Two-buffer ping-pong on the PRIORITY list.  Both buffers are
         * posted at init.  The NIC writes to the head buffer using
         * manage_local=1 (hardware-managed write pointer).  When remaining
         * space drops below UCT_CXI_AM_MIN_FREE, the NIC auto-unlinks that
         * buffer and moves to the next.  C_EVENT_UNLINK reposts the
         * consumed buffer at the tail of the list. */
        uint8_t              *rx_buf[UCT_CXI_AM_RX_NUM_BUFS];
        uct_cxi_mem_handle_t  rx_mh[UCT_CXI_AM_RX_NUM_BUFS];
        uint32_t              rx_total; /**< Total messages received (never reset) */
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
