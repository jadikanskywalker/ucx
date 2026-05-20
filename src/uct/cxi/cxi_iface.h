/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifndef UCT_CXI_IFACE_H
#define UCT_CXI_IFACE_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/api/uct.h>

#define UCT_CXI_NAME "cxi"

/**
 * CXI interface configuration.
 */
typedef struct uct_cxi_iface_config {
    uct_iface_config_t super;
} uct_cxi_iface_config_t;

/**
 * CXI interface instance.
 */
typedef struct uct_cxi_iface {
    uct_base_iface_t super;
} uct_cxi_iface_t;

UCS_CLASS_DECLARE(uct_cxi_iface_t, uct_md_h, uct_worker_h,
                  const uct_iface_params_t*, const uct_iface_config_t*)

ucs_status_t uct_cxi_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr);
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

#endif /* UCT_CXI_IFACE_H */
