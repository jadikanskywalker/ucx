/**
 * CXI device definitions.
 */

#ifndef UCT_CXI_DEVICE_H
#define UCT_CXI_DEVICE_H

#include <uct/api/uct_def.h>
#include <ucs/type/status.h>

#define UCT_CXI_DEVICE_NAME "cxi0"


/**
 * CXI device descriptor.  One per physical NIC (cxi0, cxi1, ...).
 * Populated during md_open from cxil_dev->info.
 */
typedef struct uct_cxi_device {
    char     name[UCT_DEVICE_NAME_MAX]; /**< Device name e.g. "cxi0" */
    uint32_t dev_id;                    /**< Numeric index for cxil_open_device */
    uint32_t nid;                       /**< NIC address from dev->info.nid */
} uct_cxi_device_t;


ucs_status_t uct_cxi_device_init(uct_cxi_device_t *device,
                                 const char *name, uint32_t dev_id,
                                 uint32_t nid);

void uct_cxi_device_cleanup(uct_cxi_device_t *device);

#endif /* UCT_CXI_DEVICE_H */
