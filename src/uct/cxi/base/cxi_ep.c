/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI endpoint: create, destroy, pending queue, flush and fence.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cxi_ep.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>

#include <cxi_prov_hw.h>


void uct_cxi_send_desc_put_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    ucs_mpool_put((uct_cxi_send_desc_t*)op);
}

/* Allocate an EP to the remote iface in \a params and precompute its DFAs. */
ucs_status_t uct_cxi_ep_create(const uct_ep_params_t *params, uct_ep_h *ep_p)
{
    uct_cxi_iface_t *iface;
    uct_cxi_md_t *md;
    uct_cxi_ep_t *ep;
    const uct_cxi_device_addr_t *dev_addr;
    const uct_cxi_iface_addr_t *iface_addr;
    uint8_t lac;

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);

    iface = ucs_derived_of(params->iface, uct_cxi_iface_t);
    md    = ucs_derived_of(iface->super.md, uct_cxi_md_t);

    ep = ucs_malloc(sizeof(*ep), "uct_cxi_ep");
    if (ep == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    UCS_CLASS_INIT(uct_base_ep_t, &ep->super, &iface->super);

    dev_addr   = (const uct_cxi_device_addr_t*)params->dev_addr;
    iface_addr = (const uct_cxi_iface_addr_t*)params->iface_addr;

    ep->rem_nid            = dev_addr->nid;
    ep->rem_pid            = iface_addr->pid;
    ep->outstanding        = 0;
    ep->flush_comp         = NULL;
    ep->rndv_hdr_announced = 0;
    ep->destroyed          = 0;
    ucs_arbiter_group_init(&ep->arb_group);

#ifndef UCT_CXI_DISABLE_FC
    ep->next_blocked = NULL;
    ep->fc_listed    = 0;

    /* One handshake per remote iface, however many eps are created to it. */
    ep->peer = NULL;
    if (iface->fc.enabled) {
        ep->peer = uct_cxi_peer_get(iface, ep->rem_nid, ep->rem_pid);
        if (ep->peer != NULL) {
            uct_cxi_peer_connect(iface, ep->peer);
        }
    }
#endif

    /* All DFAs are built here so the hot path needs no check. */
    for (lac = 0; lac < UCT_CXI_MAX_LACS; lac++) {
        cxi_build_dfa(ep->rem_nid, ep->rem_pid, md->pid_bits, lac,
                      &ep->dfa_rma[lac], &ep->dfa_rma_idx_ext[lac]);
    }

    cxi_build_dfa(ep->rem_nid, ep->rem_pid, md->pid_bits, UCT_CXI_PTE_AM,
                  &ep->dfa_am, &ep->dfa_am_idx_ext);
    /* Pure address arithmetic: needs no local tag PTE. */
    cxi_build_dfa(ep->rem_nid, ep->rem_pid, md->pid_bits, UCT_CXI_PTE_TAG,
                  &ep->dfa_tag, &ep->dfa_tag_idx_ext);

    ucs_debug("cxi ep %p create nid 0x%x pid %u", ep, ep->rem_nid, ep->rem_pid);

    *ep_p = &ep->super.super;
    return UCS_OK;
}

void uct_cxi_ep_free(uct_cxi_ep_t *ep)
{
    UCS_CLASS_CLEANUP(uct_base_ep_t, &ep->super);
    ucs_free(ep);
}

static void uct_cxi_ep_pending_purge_warn_cb(uct_pending_req_t *self, void *arg)
{
    ucs_warn("cxi ep %p: pending request %p (func=%p) was not purged", arg,
             self, (void*)self->func);
}

void uct_cxi_ep_destroy(uct_ep_h tl_ep)
{
    uct_cxi_ep_t *ep       = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    int ret;

    ucs_debug("cxi ep %p destroy (outstanding=%u)", ep, ep->outstanding);
    uct_cxi_ep_pending_purge(tl_ep, uct_cxi_ep_pending_purge_warn_cb, ep);
#ifndef UCT_CXI_DISABLE_FC
    if (ep->peer != NULL) {
        uct_cxi_fc_unblock_ep(ep); /* the peer must not resume a dead ep */
    }
#endif

    if (ep->outstanding == 0) {
        uct_cxi_ep_free(ep);
        return;
    }

    /* Completions find their ep through a pointer in the command, so the last
     * completion frees it (uct_cxi_iface_ep_release). */
    kh_put(uct_cxi_zombie_ep_hash, &iface->tx.zombie_eps, (uintptr_t)ep, &ret);
    if (ret >= 0) {
        ep->destroyed = 1;
        return;
    }

    /* Cannot remember it, so cannot free it later: leak it rather than free
     * memory a completion is about to dereference. */
    ucs_error("cxi ep %p: no memory to track a destroyed ep with %u sends in "
              "flight, leaking it",
              ep, ep->outstanding);
}

/*
 * Arbiter dispatch callback, run from progress. A NO_RESOURCE from req->func
 * is:
 *   - a lack of this peer's credits or a handshake in flight
 *     (iface->tx.credit_block): only this ep is parked until a grant, the CREP
 *     or a refund;
 *   - an interface-wide shortage (cmdq, pools, TX queue): STOP the dispatch.
 */
ucs_arbiter_cb_result_t
uct_cxi_ep_process_pending(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                           ucs_arbiter_elem_t *elem, void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
#ifndef UCT_CXI_DISABLE_FC
    uct_cxi_ep_t *ep       = ucs_container_of(group, uct_cxi_ep_t, arb_group);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
#endif
    ucs_status_t status;

#ifndef UCT_CXI_DISABLE_FC
    iface->tx.credit_block = 0;
#endif

    status = req->func(req);
    ucs_trace("cxi pending: process req=%p func=%p status=%s", req,
              (void*)req->func, ucs_status_string(status));
    if (status == UCS_OK) {
        return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
    }

    if (status != UCS_ERR_NO_RESOURCE) {
        return UCS_ARBITER_CB_RESULT_NEXT_GROUP;
    }

#ifndef UCT_CXI_DISABLE_FC
    if (iface->tx.credit_block) {
        /* Park just this ep; other eps carry on. */
        uct_cxi_fc_block_ep(ep);
        return UCS_ARBITER_CB_RESULT_DESCHED_GROUP;
    }
#endif

    return UCS_ARBITER_CB_RESULT_STOP;
}

/* Always queues: there is no cheap way to probe cmdq, op_pool and desc_pool. */
ucs_status_t
uct_cxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n, unsigned flags)
{
    uct_cxi_ep_t *ep       = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);

    uct_pending_req_arb_group_push(&ep->arb_group, n);
    ucs_arbiter_group_schedule(&iface->tx.arbiter, &ep->arb_group);
    ucs_trace("cxi pending: add ep=%p req=%p func=%p", ep, n, (void*)n->func);
    return UCS_OK;
}

static ucs_arbiter_cb_result_t
uct_cxi_ep_arbiter_purge_cb(ucs_arbiter_t *arbiter, ucs_arbiter_group_t *group,
                            ucs_arbiter_elem_t *elem, void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    uct_purge_cb_args_t *cb_args = arg;

    if (cb_args->cb != NULL) {
        cb_args->cb(req, cb_args->arg);
    }

    return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
}

void uct_cxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg)
{
    uct_cxi_ep_t *ep            = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface      = uct_cxi_ep_iface(ep);
    uct_purge_cb_args_t cb_args = {cb, arg};

    ucs_info("cxi pending: purge ep=%p elems=%zu", ep,
             ucs_arbiter_group_num_elems(&ep->arb_group));
    ucs_arbiter_group_purge(&iface->tx.arbiter, &ep->arb_group,
                            uct_cxi_ep_arbiter_purge_cb, &cb_args);
}

/* UCS_OK once every send on this EP is acknowledged, else UCS_INPROGRESS. */
ucs_status_t
uct_cxi_ep_flush(uct_ep_h tl_ep, unsigned flags, uct_completion_t *comp)
{
    uct_cxi_ep_t *ep = ucs_derived_of(tl_ep, uct_cxi_ep_t);

    if (ep->outstanding == 0) {
        UCT_TL_EP_STAT_FLUSH(&ep->super);
        return UCS_OK;
    }

    if (comp != NULL) {
        ucs_assert(ep->flush_comp == NULL);
        ep->flush_comp = comp;
    }

    UCT_TL_EP_STAT_FLUSH_WAIT(&ep->super);
    return UCS_INPROGRESS;
}

/* The NIC pipelines commands; CQ_FENCE holds later ones until earlier finish.
 */
ucs_status_t uct_cxi_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
    uct_cxi_ep_t *ep       = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    int ret;

    ret = cxi_cq_emit_cq_cmd(iface->tx.cmdq, C_CMD_CQ_FENCE);
    if (ucs_unlikely(ret != 0)) {
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);

    UCT_TL_EP_STAT_FENCE(&ep->super);
    return UCS_OK;
}
