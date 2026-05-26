/**
 * CXI memory domain definitions.
 */

#ifndef UCT_CXI_MD_H
#define UCT_CXI_MD_H

#include "cxi_device.h"

#include <uct/base/uct_md.h>
#include <ucs/memory/rcache.h>

#include <libcxi/libcxi.h>


typedef struct uct_cxi_md_config {
    uct_md_config_t          super;
    ucs_ternary_auto_value_t enable_ats;    /**< Enable PCIe ATS scalable map */
    ucs_ternary_auto_value_t enable_rcache; /**< Enable registration cache */
    ucs_rcache_config_t      rcache;        /**< Registration cache config */
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
    uint8_t           pid_bits;   /**< NIC PID width (cxil_dev->info.pid_bits) */
    ucs_rcache_t     *rcache;     /**< Registration cache; NULL if disabled */
    struct cxi_md    *ats_md;    /**< Scalable ATS mapping; NULL if ATS disabled */
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
 * Registration cache region.  One is allocated per unique (page-aligned) VA
 * range by the rcache infrastructure; mem_reg callbacks fill @a memh.  The
 * embedded @a memh is handed to callers as uct_mem_h so the two structs have
 * the same lifetime.
 */
typedef struct uct_cxi_rcache_region {
    ucs_rcache_region_t  super; /**< Base class — must be first */
    uct_cxi_mem_handle_t memh;  /**< Embedded handle exposed as uct_mem_h */
} uct_cxi_rcache_region_t;


/**
 * Remote key packed by mkey_pack and unpacked by rkey_unpack.
 *
 * In restricted-mode DMA the initiator drives the memory access entirely:
 * routing uses {nid, pid, ptn} from the connected EP's device_addr and
 * iface_addr; the memory itself is addressed by {iova, lac} from the rkey.
 * nid is not packed here — the EP already has it from device_addr.
 */
typedef struct uct_cxi_rkey {
    uint64_t iova; /**< Base IOVA of the registered region (from cxil_map) */
    uint8_t  lac;  /**< Logical Address Context (memory access class) */
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
