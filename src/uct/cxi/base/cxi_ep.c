/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI endpoint implementation — ep_create, ep_destroy, ep_flush, ep_fence.
 *
 * RMA operations (ep_put_zcopy, ep_get_zcopy) live in cxi_rma.c.
 *
 * ep_create builds one DFA for RMA/AMO (pid_offset = UCT_CXI_PTE_RMA) that
 * every LAC shares -- routing is LAC-independent (see cxi_iface.h).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_ep.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <ucs/sys/string.h>

#include <cxi_prov_hw.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_ep_md(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(uct_cxi_ep_iface(ep)->super.md, uct_cxi_md_t);
}


/* -------------------------------------------------------------------------
 * ep_create / ep_destroy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_create — allocate and connect an EP to a remote iface.
 *
 * Reads device_addr (nid) and iface_addr (pid) from params, stores them in
 * the EP, and precomputes the single RMA/AMO DFA (shared by every LAC).
 */
ucs_status_t uct_cxi_ep_create(const uct_ep_params_t *params, uct_ep_h *ep_p)
{
    uct_cxi_iface_t             *iface;
    uct_cxi_md_t                *md;
    uct_cxi_ep_t                *ep;
    const uct_cxi_device_addr_t *dev_addr;
    const uct_cxi_iface_addr_t  *iface_addr;

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);

    iface = ucs_derived_of(params->iface, uct_cxi_iface_t);
    md    = ucs_derived_of(iface->super.md, uct_cxi_md_t);

    ep = ucs_malloc(sizeof(*ep), "uct_cxi_ep");
    if (ep == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    UCS_CLASS_INIT(uct_base_ep_t, &ep->super, &iface->super);

    dev_addr   = (const uct_cxi_device_addr_t *)params->dev_addr;
    iface_addr = (const uct_cxi_iface_addr_t  *)params->iface_addr;

    ep->rem_nid          = dev_addr->nid;
    ep->rem_pid          = iface_addr->pid;
    ep->outstanding      = 0;
    ep->flush_comp       = NULL;
    ep->fc_blocked_until = 0;
    ucs_arbiter_group_init(&ep->arb_group);

    /* Build both DFAs at creation time so the hot path needs no check.
     * RMA/AMO DFA: pid_offset = UCT_CXI_PTE_RMA (one PTE, all LACs).
     * AM DFA:      pid_offset = UCT_CXI_PTE_AM (fixed protocol constant). */
    cxi_build_dfa(ep->rem_nid, ep->rem_pid, (uint32_t)md->pid_bits,
                  (uint32_t)UCT_CXI_PTE_RMA,
                  &ep->dfa_rma, &ep->dfa_rma_idx_ext);
    cxi_build_dfa(ep->rem_nid, ep->rem_pid, (uint32_t)md->pid_bits,
                  (uint32_t)UCT_CXI_PTE_AM, &ep->dfa_am, &ep->dfa_am_idx_ext);

    ucs_debug("cxi ep %p create nid 0x%x pid %u",
              ep, ep->rem_nid, ep->rem_pid);

    *ep_p = &ep->super.super;
    return UCS_OK;
}

static void uct_cxi_ep_pending_purge_warn_cb(uct_pending_req_t *self, void *arg)
{
    uct_ep_h ep = arg;
    ucs_warn("cxi ep %p: pending request %p (func=%p) was not purged",
             ep, self, (void*)self->func);
}

void uct_cxi_ep_destroy(uct_ep_h tl_ep)
{
    uct_cxi_ep_t *ep = ucs_derived_of(tl_ep, uct_cxi_ep_t);

    ucs_debug("cxi ep %p destroy (outstanding=%u)", ep, ep->outstanding);
    uct_cxi_ep_pending_purge(tl_ep, uct_cxi_ep_pending_purge_warn_cb, ep);
    ucs_free(ep);
}


/* -------------------------------------------------------------------------
 * pending_add / pending_purge
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_process_pending — arbiter dispatch callback, invoked from
 * iface_progress() once TX completions have freed cmdq/pool resources.
 *
 * Unlike IB RC, CXI has no per-EP remote flow-control credits — cmdq,
 * op_pool, and desc_pool are all iface-global.  So if one EP's pending
 * callback hits NO_RESOURCE, no other EP can progress this round either;
 * STOP halts the whole dispatch instead of RC's four-way EP-vs-iface split.
 */
ucs_arbiter_cb_result_t
uct_cxi_ep_process_pending(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                            ucs_arbiter_elem_t *elem, void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    ucs_status_t       status;

    status = req->func(req);
    /* TEMPORARY: confirms the dispatch loop is actually retrying queued
     * sends and shows how each attempt resolves. */
    ucs_trace("cxi pending: process req=%p func=%p status=%s",
             req, (void*)req->func, ucs_status_string(status));
    if (status == UCS_OK) {
        return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
    } else if (status == UCS_ERR_NO_RESOURCE) {
        return UCS_ARBITER_CB_RESULT_STOP;
    }
    return UCS_ARBITER_CB_RESULT_NEXT_GROUP;
}

/*
 * uct_cxi_ep_pending_add — queue a callback to retry once resources free up.
 *
 * Unconditionally queues (no UCS_ERR_BUSY fast path): CXI has three distinct
 * resource pools (cmdq, op_pool, desc_pool) and no cheap way to probe "do I
 * have resources right now" across all of them, so we always defer to the
 * arbiter dispatch in iface_progress() rather than trying to special-case
 * the immediately-retryable case.
 */
ucs_status_t uct_cxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                     unsigned flags)
{
    uct_cxi_ep_t     *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t  *iface = uct_cxi_ep_iface(ep);

    uct_pending_req_arb_group_push(&ep->arb_group, n);
    ucs_arbiter_group_schedule(&iface->tx.arbiter, &ep->arb_group);
    /* TEMPORARY: confirms pending_add is actually reached (vs the caller
     * silently swallowing NO_RESOURCE) and which EP/req queued. */
    ucs_trace("cxi pending: add ep=%p req=%p func=%p", ep, n, (void*)n->func);
    return UCS_OK;
}

static ucs_arbiter_cb_result_t
uct_cxi_ep_arbiter_purge_cb(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                             ucs_arbiter_elem_t *elem, void *arg)
{
    uct_pending_req_t   *req      = ucs_container_of(elem, uct_pending_req_t,
                                                       priv);
    uct_purge_cb_args_t *cb_args  = arg;

    if (cb_args->cb != NULL) {
        cb_args->cb(req, cb_args->arg);
    }
    return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
}

void uct_cxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                               void *arg)
{
    uct_cxi_ep_t        *ep        = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t     *iface     = uct_cxi_ep_iface(ep);
    uct_purge_cb_args_t  cb_args   = {cb, arg};

    /* TEMPORARY: confirms purge runs and how many elements it found. */
    ucs_info("cxi pending: purge ep=%p elems=%zu", ep,
             ucs_arbiter_group_num_elems(&ep->arb_group));
    ucs_arbiter_group_purge(&iface->tx.arbiter, &ep->arb_group,
                             uct_cxi_ep_arbiter_purge_cb, &cb_args);
}


/* -------------------------------------------------------------------------
 * ep_flush / ep_fence
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_flush — poll-based flush.
 *
 * Returns UCS_OK when all sends posted on this EP have been acknowledged.
 * Returns UCS_INPROGRESS while ACKs are pending.
 */
ucs_status_t uct_cxi_ep_flush(uct_ep_h tl_ep, unsigned flags,
                               uct_completion_t *comp)
{
    uct_cxi_ep_t *ep = ucs_derived_of(tl_ep, uct_cxi_ep_t);

    if (ep->outstanding == 0) {
        UCT_TL_EP_STAT_FLUSH(ucs_derived_of(tl_ep, uct_base_ep_t));
        return UCS_OK;
    }

    if (comp != NULL) {
        ucs_assert(ep->flush_comp == NULL);
        ep->flush_comp = comp;
    }

    UCT_TL_EP_STAT_FLUSH_WAIT(ucs_derived_of(tl_ep, uct_base_ep_t));
    return UCS_INPROGRESS;
}

/*
 * uct_cxi_ep_fence — emit C_CMD_CQ_FENCE to stall NIC pipeline.
 *
 * The CXI CMDQ is submission-ordered, but the NIC pipelines execution:
 * a later command can begin before an earlier one finishes, allowing
 * reordering in the fabric.  C_CMD_CQ_FENCE stalls subsequent commands
 * until all prior commands have completed execution.
 */
ucs_status_t uct_cxi_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_cxi_iface_t);
    int ret;

    ret = cxi_cq_emit_cq_cmd(iface->tx.cmdq, C_CMD_CQ_FENCE);
    if (ucs_unlikely(ret != 0)) {
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tx.cmdq);

    UCT_TL_EP_STAT_FENCE(ucs_derived_of(tl_ep, uct_base_ep_t));
    return UCS_OK;
}
