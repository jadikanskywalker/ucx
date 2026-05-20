/**
 * Minimal CXI UCT interface wiring.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"
#include "base/cxi_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/sys/stubs.h>
#include <ucs/sys/string.h>

static ucs_config_field_t uct_cxi_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_cxi_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},
    {NULL}
};

static UCS_CLASS_DEFINE_DELETE_FUNC(uct_cxi_iface_t, uct_iface_t);

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
    .iface_event_fd_get       = (uct_iface_event_fd_get_func_t)ucs_empty_function_return_unsupported,
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
    .iface_mem_element_pack = (uct_iface_mem_element_pack_func_t)ucs_empty_function_return_unsupported,
    .ep_query               = (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
    .ep_invalidate          = (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2    = (uct_ep_connect_to_ep_v2_func_t)ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2  = uct_cxi_iface_is_reachable_v2,
    .ep_is_connected        = (uct_ep_is_connected_func_t)ucs_empty_function_return_zero_int,
    .ep_get_device_ep       = (uct_ep_get_device_ep_func_t)ucs_empty_function_return_unsupported
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
    UCT_CHECK_PARAM(params->field_mask & UCT_IFACE_PARAM_FIELD_OPEN_MODE,
                    "UCT_IFACE_PARAM_FIELD_OPEN_MODE is not defined");
    if (!(params->open_mode & UCT_IFACE_OPEN_MODE_DEVICE)) {
        ucs_error("only UCT_IFACE_OPEN_MODE_DEVICE is supported");
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

    ucs_debug("uct_cxi_iface_init: iface=%p md=%p worker=%p", self, (void*)md,
              (void*)worker);
    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_cxi_iface_t)
{
    ucs_debug("uct_cxi_iface_cleanup: iface=%p", self);
    /* No CXI-specific resources yet. */
}

UCS_CLASS_DEFINE(uct_cxi_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_cxi_iface_t, uct_iface_t, uct_md_h, uct_worker_h,
                          const uct_iface_params_t*, const uct_iface_config_t*);

ucs_status_t uct_cxi_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);

    uct_base_iface_query(&iface->super, iface_attr);
    iface_attr->cap.flags       = 0;
    iface_attr->bandwidth.dedicated = 0;
    iface_attr->bandwidth.shared    = 0;
    iface_attr->overhead        = 0;
    iface_attr->latency         = ucs_linear_func_make(0, 0);
    iface_attr->max_num_eps     = 0;
    iface_attr->iface_addr_len  = 0;
    iface_attr->device_addr_len = 0;

    ucs_debug("uct_cxi_iface_query: iface=%p", iface);
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
    return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_cxi_iface_get_address(uct_iface_h tl_iface,
                                       uct_iface_addr_t *iface_addr)
{
    return UCS_ERR_UNSUPPORTED;
}

int uct_cxi_iface_is_reachable(uct_iface_h tl_iface,
                               const uct_device_addr_t *dev_addr,
                               const uct_iface_addr_t *iface_addr)
{
    return 0;
}

int uct_cxi_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                  const uct_iface_is_reachable_params_t *params)
{
    return 0;
}

UCT_TL_DEFINE_ENTRY(&uct_cxi_component, cxi, uct_cxi_query_devices,
                    uct_cxi_iface_t, "CXI_", uct_cxi_iface_config_table,
                    uct_cxi_iface_config_t);

UCT_SINGLE_TL_INIT(&uct_cxi_component, cxi,,,)
