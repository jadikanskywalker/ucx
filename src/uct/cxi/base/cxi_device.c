/**
 * CXI device implementation.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_device.h"

#include <ucs/debug/log.h>
#include <ucs/sys/string.h>

ucs_status_t uct_cxi_device_init(uct_cxi_device_t *device, const char *name,
                                 uint32_t dev_id, uint32_t nid)
{
    ucs_strncpy_safe(device->name, name, sizeof(device->name));
    device->dev_id = dev_id;
    device->nid    = nid;

    ucs_debug("cxi device init name %s dev_id %u nid 0x%x",
              device->name, device->dev_id, device->nid);
    return UCS_OK;
}

void uct_cxi_device_cleanup(uct_cxi_device_t *device)
{
    ucs_debug("cxi device cleanup name %s", device->name);
}
