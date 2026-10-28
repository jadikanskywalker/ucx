/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI device definitions.
 */

#ifndef UCT_CXI_DEVICE_H
#define UCT_CXI_DEVICE_H

#include <uct/api/uct_def.h>


/**
 * CXI device descriptor. One per physical NIC (cxi0, cxi1, ...). Populated
 * during md_open from cxil_dev->info.
 */
typedef struct uct_cxi_device {
    /* Device name, e.g. "cxi0" */
    char     name[UCT_DEVICE_NAME_MAX];
    /* Numeric index for cxil_open_device */
    uint32_t dev_id;
    /* NIC address from dev->info.nid */
    uint32_t nid;
} uct_cxi_device_t;


void uct_cxi_device_init(uct_cxi_device_t *device, const char *name,
                         uint32_t dev_id, uint32_t nid);

#endif /* UCT_CXI_DEVICE_H */
