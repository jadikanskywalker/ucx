/**
 * CXI memory domain definitions.
 */

#ifndef UCT_CXI_MD_H
#define UCT_CXI_MD_H

#include "cxi_device.h"

#include <uct/base/uct_md.h>

#include <libcxi/libcxi.h>


typedef struct uct_cxi_md_config {
    uct_md_config_t super;
} uct_cxi_md_config_t;


/**
 * CXI memory domain.  Holds the open device handle and the LNI, which gate
 * all hardware resources (CMDQs, EVTQs, PTEs, memory maps).  Opened once per
 * physical device per process; multiple ifaces share the same MD.
 */
typedef struct uct_cxi_md {
    uct_md_t          super;      /**< Base MD — must be first */
    uct_cxi_device_t  device;     /**< Device descriptor (name, dev_id, nid) */
    int               refcount;   /**< Reference count (ifaces using this MD) */
    /* hardware handles — valid after md_open, released in md_close */
    struct cxil_dev  *cxi_dev;    /**< Opened libcxi device */
    struct cxil_lni  *cxi_lni;    /**< LNI allocated for svc_id */
    uint32_t          svc_id;     /**< Service ID from SLINGSHOT_SVC_IDS */
    uint16_t          vni;        /**< VNI from SLINGSHOT_VNIS */
} uct_cxi_md_t;


/**
 * Memory handle returned by mem_reg.  Wraps the libcxi memory descriptor,
 * which carries the IOVA, length, and LAC needed for DMA descriptors.
 * Keep this struct small: one exists per registered memory region.
 */
typedef struct uct_cxi_mem_handle {
    struct cxi_md *cxi_md; /**< Memory descriptor from cxil_map */
} uct_cxi_mem_handle_t;


/**
 * Remote key packed by mkey_pack and unpacked by rkey_unpack.
 * Contains enough information to address a DMA target: the peer's NIC
 * address, the IOVA of the registered buffer, and the LAC tag.
 */
typedef struct uct_cxi_rkey {
    uint32_t nid;  /**< Peer NIC address */
    uint64_t iova; /**< Base IOVA in the peer's address space */
    uint8_t  lac;  /**< Memory access class from the peer's cxi_md */
} UCS_S_PACKED uct_cxi_rkey_t;


extern uct_component_t uct_cxi_component;


ucs_status_t uct_cxi_query_md_resources(uct_component_h component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p);

ucs_status_t uct_cxi_md_open(uct_component_h component, const char *md_name,
                             const uct_md_config_t *md_config, uct_md_h *md_p);

void uct_cxi_md_close(uct_md_h md);

ucs_status_t uct_cxi_md_query(uct_md_h md, uct_md_attr_v2_t *md_attr);

#endif /* UCT_CXI_MD_H */
