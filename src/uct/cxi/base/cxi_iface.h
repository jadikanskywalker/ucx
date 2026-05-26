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

#include <libcxi/libcxi.h>


#define UCT_CXI_NAME "cxi"

/* Event queue sizing. */
#define UCT_CXI_EQ_NUM_EVENTS  1024U
#define UCT_CXI_EQ_ENTRY_SIZE  64U   /* sizeof(union c_event) */
#define UCT_CXI_EQ_BUF_LEN    (UCT_CXI_EQ_NUM_EVENTS * UCT_CXI_EQ_ENTRY_SIZE)

/* Command queue depth. */
#define UCT_CXI_CMDQ_DEPTH     256U


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
 * Both fields are required by the initiator EP to construct the DFA
 * (Destination Fabric Address) for restricted-mode DMA:
 *
 *   cxi_build_dfa(nid, pid, md->pid_bits, ptn, &dfa, &idx_ext)
 *
 * nid comes from device_addr; {iova, lac} come from the rkey.
 * ptn is the portal table entry used as a routing anchor on the target —
 * in restricted mode the PTE receives completion events but posts no LEs.
 */
typedef struct uct_cxi_iface_addr {
    uint32_t pid; /**< CXI Port ID assigned by cxil_alloc_domain (0-510) */
    uint32_t ptn; /**< Portal table number; routing anchor for restricted DMA */
} UCS_S_PACKED uct_cxi_iface_addr_t;


/**
 * CXI interface configuration.
 */
typedef struct uct_cxi_iface_config {
    uct_iface_config_t super;
} uct_cxi_iface_config_t;


/**
 * CXI interface instance.
 *
 * Holds all libcxi hardware resources allocated at iface_open.  Resources are
 * listed in allocation order and must be destroyed in strict reverse order.
 *
 * The PTE is used in routing-only mode (no list entries posted): restricted
 * mode DMA bypasses LE matching and addresses memory directly via {lac, iova}
 * from the rkey.  The PTE exists solely so the NIC has a valid endpoint at
 * {pid, ptn} to route completion events.
 */
typedef struct uct_cxi_iface {
    uct_base_iface_t      super;    /**< Must be first */
    /* libcxi resources — allocated in order below, destroyed in reverse */
    struct cxil_wait_obj *wait_obj; /**< Interrupt / epoll fd for progress */
    void                 *eq_buf;   /**< mmap backing buffer for evtq */
    struct cxi_md        *eq_md;    /**< cxil_map registration of eq_buf */
    struct cxi_eq        *evtq;     /**< Event queue (shared by CMDQs & PTE) */
    struct cxi_cp        *cp;       /**< TX communication profile */
    struct cxi_cq        *tx_cmdq; /**< TX command queue (CXI_CQ_IS_TX) */
    struct cxi_cq        *tg_cmdq; /**< Target (initiator-side) command queue */
    struct cxil_domain   *domain;  /**< VNI + PID domain binding */
    struct cxil_pte      *pte;     /**< Portal table entry (routing; no LEs) */
    struct cxil_pte_map  *pte_map; /**< Active domain → PTE mapping */
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
