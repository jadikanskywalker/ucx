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
 * Per-send-op tracking record.
 *
 * Allocated from iface->tx.op_pool for zcopy/short ops, or embedded as the
 * first field of uct_cxi_send_desc_t for bcopy ops.  Stored via user_ptr so
 * that iface_progress can retrieve it on C_EVENT_ACK or C_EVENT_REPLY.
 *
 * handler: NULL for zcopy/short (default path: invoke comp, mpool_put op).
 *          Set for bcopy: handler owns completion + returns desc to pool.
 */
typedef struct uct_cxi_send_op {
    struct uct_cxi_ep *ep;      /**< Owning EP — used to decrement outstanding */
    uct_completion_t  *comp;    /**< Caller completion callback, or NULL       */
    void (*handler)(struct uct_cxi_send_op *); /**< NULL = default zcopy path  */
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
 *   With the default build (UCT_CXI_MAX_LACS = 1) only dfa_rma[0] is built.
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
    unsigned          outstanding;     /**< In-flight send ops for this EP */
    uct_completion_t *flush_comp;     /**< Pending flush completion, or NULL */
    ucs_arbiter_group_t arb_group;     /**< Pending-request queue for this EP */
} uct_cxi_ep_t;


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
