/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT interface implementation.
 *
 * Allocates the per-iface libcxi hardware resources (event queue, command
 * queues, domain, portal table entry) and exposes the {nid, pid, ptn} address
 * that a remote EP needs to route restricted-mode DMA operations here.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/sys/stubs.h>
#include <ucs/sys/string.h>

#include <sys/mman.h>   /* mmap / munmap */
#include <errno.h>
#include <string.h>     /* strerror */


/* Inline accessor — avoids repeated ucs_derived_of casts. */
static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_iface_md(uct_cxi_iface_t *iface)
{
    return ucs_derived_of(iface->super.md, uct_cxi_md_t);
}


static ucs_config_field_t uct_cxi_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_cxi_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},
    {NULL}
};

static UCS_CLASS_DEFINE_DELETE_FUNC(uct_cxi_iface_t, uct_iface_t);

/* Forward declaration for ops table. */
ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p);

static uct_iface_ops_t uct_cxi_iface_ops = {
    .ep_put_short             = (uct_ep_put_short_func_t)ucs_empty_function_return_unsupported,
    .ep_put_bcopy             = (uct_ep_put_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_put_zcopy             = (uct_ep_put_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_get_short             = (uct_ep_get_short_func_t)ucs_empty_function_return_unsupported,
    .ep_get_bcopy             = (uct_ep_get_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_get_zcopy             = (uct_ep_get_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_am_short              = (uct_ep_am_short_func_t)ucs_empty_function_return_unsupported,
    .ep_am_short_iov          = (uct_ep_am_short_iov_func_t)ucs_empty_function_return_unsupported,
    .ep_am_bcopy              = (uct_ep_am_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_am_zcopy              = (uct_ep_am_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic_cswap64        = (uct_ep_atomic_cswap64_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic_cswap32        = (uct_ep_atomic_cswap32_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic32_post         = (uct_ep_atomic32_post_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic64_post         = (uct_ep_atomic64_post_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic32_fetch        = (uct_ep_atomic32_fetch_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic64_fetch        = (uct_ep_atomic64_fetch_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_short       = (uct_ep_tag_eager_short_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_bcopy       = (uct_ep_tag_eager_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_zcopy       = (uct_ep_tag_eager_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_zcopy        = (uct_ep_tag_rndv_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_cancel       = (uct_ep_tag_rndv_cancel_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_request      = (uct_ep_tag_rndv_request_func_t)ucs_empty_function_return_unsupported,
    .iface_tag_recv_zcopy     = (uct_iface_tag_recv_zcopy_func_t)ucs_empty_function_return_unsupported,
    .iface_tag_recv_cancel    = (uct_iface_tag_recv_cancel_func_t)ucs_empty_function_return_unsupported,
    .ep_pending_add           = (uct_ep_pending_add_func_t)ucs_empty_function_return_unsupported,
    .ep_pending_purge         = (uct_ep_pending_purge_func_t)ucs_empty_function,
    .ep_flush                 = (uct_ep_flush_func_t)ucs_empty_function_return_unsupported,
    .ep_fence                 = (uct_ep_fence_func_t)ucs_empty_function_return_unsupported,
    .ep_check                 = (uct_ep_check_func_t)ucs_empty_function_return_unsupported,
    .ep_create                = (uct_ep_create_func_t)ucs_empty_function_return_unsupported,
    .ep_connect               = (uct_ep_connect_func_t)ucs_empty_function_return_unsupported,
    .ep_disconnect            = (uct_ep_disconnect_func_t)ucs_empty_function_return_unsupported,
    .cm_ep_conn_notify        = (uct_cm_ep_conn_notify_func_t)ucs_empty_function_return_unsupported,
    .ep_destroy               = (uct_ep_destroy_func_t)ucs_empty_function_return_unsupported,
    .ep_get_address           = (uct_ep_get_address_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep         = (uct_ep_connect_to_ep_func_t)ucs_empty_function_return_unsupported,
    .iface_accept             = (uct_iface_accept_func_t)ucs_empty_function_return_unsupported,
    .iface_reject             = (uct_iface_reject_func_t)ucs_empty_function_return_unsupported,
    .iface_flush              = uct_cxi_iface_flush,
    .iface_fence              = uct_base_iface_fence,
    .iface_progress_enable    = uct_base_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = (uct_iface_progress_func_t)ucs_empty_function_return_zero,
    .iface_event_fd_get       = uct_cxi_iface_event_fd_get,
    .iface_event_arm          = (uct_iface_event_arm_func_t)ucs_empty_function_return_unsupported,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_cxi_iface_t),
    .iface_query              = uct_cxi_iface_query,
    .iface_get_device_address = uct_cxi_iface_get_device_address,
    .iface_get_address        = uct_cxi_iface_get_address,
    .iface_is_reachable       = uct_cxi_iface_is_reachable
};

static uct_iface_internal_ops_t uct_cxi_iface_internal_ops = {
    .iface_query_v2         = uct_iface_base_query_v2,
    .iface_estimate_perf    = uct_base_iface_estimate_perf,
    .iface_vfs_refresh      = (uct_iface_vfs_refresh_func_t)ucs_empty_function,
    .ep_query               = (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
    .ep_invalidate          = (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2    = (uct_ep_connect_to_ep_v2_func_t)ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2  = uct_cxi_iface_is_reachable_v2,
    .ep_is_connected        = (uct_ep_is_connected_func_t)ucs_empty_function_return_zero_int,
    .ep_get_device_ep       = (uct_ep_get_device_ep_func_t)ucs_empty_function_return_unsupported,
    .ep_put_sgl_zcopy       = (uct_ep_put_sgl_zcopy_func_t)ucs_empty_function_return_unsupported
};

ucs_status_t uct_cxi_query_devices(uct_md_h md,
                                    uct_tl_device_resource_t **devices_p,
                                    unsigned *num_devices_p)
{
    uct_cxi_md_t             *cxi_md  = ucs_derived_of(md, uct_cxi_md_t);
    uct_tl_device_resource_t *devices;

    devices = ucs_calloc(1, sizeof(*devices), "cxi devices");
    if (devices == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    ucs_strncpy_safe(devices[0].name, cxi_md->device.name,
                     sizeof(devices[0].name));
    devices[0].type       = UCT_DEVICE_TYPE_NET;
    devices[0].sys_device = UCS_SYS_DEVICE_ID_UNKNOWN;

    ucs_debug("cxi query devices md %p name %s nid 0x%x",
              cxi_md, devices[0].name, cxi_md->device.nid);

    *devices_p     = devices;
    *num_devices_p = 1;
    return UCS_OK;
}

UCS_CLASS_INIT_FUNC(uct_cxi_iface_t, uct_md_h md, uct_worker_h worker,
                    const uct_iface_params_t *params,
                    const uct_iface_config_t *tl_config)
{
    uct_cxi_md_t              *cxi_md = ucs_derived_of(md, uct_cxi_md_t);
    struct cxil_lni           *lni    = cxi_md->cxi_lni;
    struct cxi_eq_attr         eq_attr;
    struct cxi_cq_alloc_opts   cq_opts;
    struct cxi_pt_alloc_opts   pt_opts;
    ucs_status_t               status;
    int                        ret;

    UCT_CHECK_PARAM(params->field_mask & UCT_IFACE_PARAM_FIELD_OPEN_MODE,
                    "UCT_IFACE_PARAM_FIELD_OPEN_MODE is not defined");
    if (!(params->open_mode & UCT_IFACE_OPEN_MODE_DEVICE)) {
        ucs_error("cxi: only UCT_IFACE_OPEN_MODE_DEVICE is supported");
        return UCS_ERR_UNSUPPORTED;
    }

    (void)ucs_derived_of(tl_config, uct_cxi_iface_config_t);

    UCS_CLASS_CALL_SUPER_INIT(
            uct_base_iface_t, &uct_cxi_iface_ops, &uct_cxi_iface_internal_ops,
            md, worker, params,
            tl_config UCS_STATS_ARG(
                    (params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) ?
                            params->stats_root :
                            NULL) UCS_STATS_ARG(UCT_CXI_NAME));

    /* Step 2: allocate the wait object (epoll fd for event-driven progress). */
    ret = cxil_alloc_wait_obj(lni, &self->wait_obj);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_wait_obj failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* Step 3: mmap a private anonymous buffer for the event queue ring. */
    self->eq_buf = mmap(NULL, UCT_CXI_EQ_BUF_LEN,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (self->eq_buf == MAP_FAILED) {
        ucs_error("cxi mmap eq_buf size %zu failed: %m", (size_t)UCT_CXI_EQ_BUF_LEN);
        status = UCS_ERR_NO_MEMORY;
        goto err_destroy_wait_obj;
    }

    /* Step 4: pin the EQ buffer so the NIC can DMA into it. */
    ret = cxil_map(lni, self->eq_buf, UCT_CXI_EQ_BUF_LEN,
                   CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE,
                   NULL, &self->eq_md);
    if (ret != 0) {
        ucs_error("cxi cxil_map eq_buf failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_munmap_eq;
    }

    /* Step 5: allocate the event queue backed by the pinned buffer. */
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.queue     = self->eq_buf;
    eq_attr.queue_len = UCT_CXI_EQ_BUF_LEN;
    ret = cxil_alloc_evtq(lni, self->eq_md, &eq_attr,
                          self->wait_obj, NULL, &self->evtq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_evtq failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_eq;
    }

    /* Step 6: allocate a TX communication profile (traffic class policy). */
    ret = cxil_alloc_cp(lni, cxi_md->vni,
                        CXI_TC_BEST_EFFORT, CXI_TC_TYPE_DEFAULT, &self->cp);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cp vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_evtq;
    }

    /* Step 7: TX command queue — posts go to the fabric. */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    cq_opts.flags = CXI_CQ_IS_TX;
    cq_opts.lcid  = self->cp->lcid;
    ret = cxil_alloc_cmdq(lni, self->evtq, &cq_opts, &self->tx_cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tx failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_cp;
    }

    /* Step 8: target command queue — used by the NIC for incoming completions. */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    ret = cxil_alloc_cmdq(lni, self->evtq, &cq_opts, &self->tg_cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tg failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tx_cmdq;
    }

    /* Step 9: allocate the VNI+PID domain — this is what "pid" identifies. */
    ret = cxil_alloc_domain(lni, cxi_md->vni, C_PID_ANY, &self->domain);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_domain vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tg_cmdq;
    }

    /*
     * Step 10: allocate the portal table entry.
     *
     * In restricted mode DMA the NIC routes the operation to {pid, ptn} via
     * the DFA, but does NOT match list entries.  The PTE is needed for routing
     * and for completion event delivery; we do not post any LEs.
     */
    memset(&pt_opts, 0, sizeof(pt_opts));
    ret = cxil_alloc_pte(lni, self->evtq, &pt_opts, &self->pte);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_domain;
    }

    /* Step 11: activate the PTE by mapping it to the domain. */
    ret = cxil_map_pte(self->pte, self->domain, 0, false, &self->pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pte;
    }

    ucs_info("cxi iface open %p nid 0x%x pid %u ptn %u pid_bits %u",
              self, cxi_md->device.nid, self->domain->pid,
              self->pte->ptn, (unsigned)cxi_md->pid_bits);
    return UCS_OK;

err_destroy_pte:
    cxil_destroy_pte(self->pte);
err_destroy_domain:
    cxil_destroy_domain(self->domain);
err_destroy_tg_cmdq:
    cxil_destroy_cmdq(self->tg_cmdq);
err_destroy_tx_cmdq:
    cxil_destroy_cmdq(self->tx_cmdq);
err_destroy_cp:
    cxil_destroy_cp(self->cp);
err_destroy_evtq:
    cxil_destroy_evtq(self->evtq);
err_unmap_eq:
    cxil_unmap(self->eq_md);
err_munmap_eq:
    munmap(self->eq_buf, UCT_CXI_EQ_BUF_LEN);
err_destroy_wait_obj:
    cxil_destroy_wait_obj(self->wait_obj);
err:
    return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_cxi_iface_t)
{
    int ret;

    /* Remove progress callback before tearing down hardware resources. */
    uct_base_iface_progress_disable(&self->super.super,
                                    UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);

    /* Strict LIFO — reverse of INIT allocation order. */
    ret = cxil_unmap_pte(self->pte_map);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap_pte failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_pte(self->pte);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_pte failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_domain(self->domain);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_domain failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cmdq(self->tg_cmdq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cmdq tg failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cmdq(self->tx_cmdq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cmdq tx failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cp(self->cp);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cp failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_evtq(self->evtq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_evtq failed: %s", strerror(-ret));
    }

    ret = cxil_unmap(self->eq_md);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap eq_md failed: %s", strerror(-ret));
    }

    munmap(self->eq_buf, UCT_CXI_EQ_BUF_LEN);

    ret = cxil_destroy_wait_obj(self->wait_obj);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_wait_obj failed: %s", strerror(-ret));
    }

    ucs_debug("cxi iface close %p", self);
}

UCS_CLASS_DEFINE(uct_cxi_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_cxi_iface_t, uct_iface_t, uct_md_h, uct_worker_h,
                          const uct_iface_params_t*, const uct_iface_config_t*);

ucs_status_t uct_cxi_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);

    uct_base_iface_query(&iface->super, iface_attr);

    /* Phase 2: no data-path operations wired yet; cap.flags must match the
     * ops table (AGENTS.md rule — wrong flags cause runtime failures). */
    iface_attr->cap.flags            = 0;
    iface_attr->device_addr_len      = sizeof(uct_cxi_device_addr_t);
    iface_attr->iface_addr_len       = sizeof(uct_cxi_iface_addr_t);
    iface_attr->ep_addr_len          = 0;
    iface_attr->max_conn_priv        = 0;
    iface_attr->max_num_eps          = UCS_MEMUNITS_INF;
    iface_attr->bandwidth.dedicated  = 25000.0 * UCS_MBYTE; /* 200 Gb/s */
    iface_attr->bandwidth.shared     = 0;
    iface_attr->latency              = ucs_linear_func_make(1500e-9, 0);
    iface_attr->overhead             = 80e-9;
    iface_attr->priority             = 0;

    return UCS_OK;
}

ucs_status_t uct_cxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                  uct_completion_t *comp)
{
    return comp == NULL ? UCS_OK : UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_cxi_iface_get_device_address(uct_iface_h tl_iface,
                                               uct_device_addr_t *dev_addr)
{
    uct_cxi_iface_t       *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_device_addr_t *a     = (uct_cxi_device_addr_t *)dev_addr;

    a->nid = uct_cxi_iface_md(iface)->device.nid;
    return UCS_OK;
}

ucs_status_t uct_cxi_iface_get_address(uct_iface_h tl_iface,
                                        uct_iface_addr_t *iface_addr)
{
    uct_cxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_iface_addr_t *a     = (uct_cxi_iface_addr_t *)iface_addr;

    a->pid = iface->domain->pid;
    a->ptn = iface->pte->ptn;
    return UCS_OK;
}

int uct_cxi_iface_is_reachable(uct_iface_h tl_iface,
                                const uct_device_addr_t *dev_addr,
                                const uct_iface_addr_t *iface_addr)
{
    return 1; /* All Slingshot NIDs are fabric-reachable. */
}

int uct_cxi_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                   const uct_iface_is_reachable_params_t *params)
{
    return uct_iface_is_reachable_params_valid(
                   params, UCT_IFACE_IS_REACHABLE_FIELD_DEVICE_ADDR) &&
           uct_iface_scope_is_reachable(tl_iface, params);
}

ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    *fd_p = cxil_get_wait_obj_fd(iface->wait_obj);
    return UCS_OK;
}

UCT_TL_DEFINE_ENTRY(&uct_cxi_component, cxi, uct_cxi_query_devices,
                    uct_cxi_iface_t, "CXI_", uct_cxi_iface_config_table,
                    uct_cxi_iface_config_t);

UCT_SINGLE_TL_INIT(&uct_cxi_component, cxi, ctor,,)
