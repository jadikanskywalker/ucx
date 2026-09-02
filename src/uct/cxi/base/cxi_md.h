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
    ucs_ternary_auto_value_t enable_dmabuf; /**< Prefer a dmabuf fd for device mem */
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
    int               dmabuf_enabled; /**< Advertise UCT_MD_FLAG_REG_DMABUF */
} uct_cxi_md_t;


/**
 * Memory handle returned by mem_reg.  Wraps the libcxi memory descriptor
 * plus one precomputed field for the DMA hot path.
 *
 * iova_offset = cxi_md->iova - base_VA
 *
 * This lets ep_put_zcopy compute the local NIC-visible address with a single
 * addition: local_iova = iova_offset + buffer_VA.  Without it the initiator
 * would need base_VA as a separate field and perform a subtraction per send.
 *
 * For ATS mode iova_offset = ats_md->iova (base_VA = 0 for the scalable map).
 * For pinned mode iova_offset = cxi_md->iova - address (address from cxil_map).
 */
typedef struct uct_cxi_mem_handle {
    struct cxi_md *cxi_md;      /**< Libcxi descriptor; needed for cxil_unmap
                                 *   and for cxi_md->lac in DMA commands       */
    uint64_t       iova_offset; /**< Precomputed: cxi_md->iova - cxi_md->va
                                 *   (page_IOVA - page_VA).
                                 *   NIC address of any buf in this registration:
                                 *   IOVA(buf) = iova_offset + buf_VA          */
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
/**
 * Remote key packed by mkey_pack and unpacked by rkey_unpack.
 *
 * iova stores iova_offset = cxi_md->iova - base_VA, so the initiator can
 * compute the target's NIC-visible address with one addition:
 *   remote_iova = rkey->iova + remote_addr
 *
 * This works for both pinned and ATS registrations.  The initiator's NIC
 * cannot resolve the target's VA directly — IOVAs are per-LNI and private
 * to the target's IOMMU namespace — so the target must include IOVA info.
 */
typedef struct uct_cxi_rkey {
    uint64_t iova; /**< iova_offset = cxi_md->iova - base_VA (see above) */
    uint8_t  lac;  /**< Logical Address Context (memory access class)     */
} UCS_S_PACKED uct_cxi_rkey_t;


extern uct_component_t uct_cxi_component;

/* Shared registration helpers used by both cxi_md.c and cxi_iface.c. */
struct cxil_lni;
ucs_status_t uct_cxi_do_map(struct cxil_lni *lni, void *address, size_t length,
                             int dmabuf_fd, size_t dmabuf_offset,
                             ucs_memory_type_t mem_type,
                             uct_cxi_mem_handle_t *mh);
void uct_cxi_do_unmap(uct_cxi_mem_handle_t *mh);


ucs_status_t uct_cxi_query_md_resources(uct_component_h component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p);

ucs_status_t uct_cxi_md_open(uct_component_h component, const char *md_name,
                             const uct_md_config_t *md_config, uct_md_h *md_p);

void uct_cxi_md_close(uct_md_h md);

ucs_status_t uct_cxi_md_query(uct_md_h md, uct_md_attr_v2_t *md_attr);

#endif /* UCT_CXI_MD_H */
