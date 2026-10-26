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


/** CXI memory domain: the open device and its LNI, shared by all ifaces. */
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
 * Memory handle from mem_reg. iova_offset (cxi_md->iova - base VA) gives the
 * NIC address of a buffer as iova_offset + buffer VA. In ATS mode it is
 * ats_md->iova (base VA 0).
 */
typedef struct uct_cxi_mem_handle {
    struct cxi_md *cxi_md;      /**< Libcxi descriptor; needed for cxil_unmap
                                 *   and for cxi_md->lac in DMA commands       */
    uint64_t       iova_offset; /**< cxi_md->iova - cxi_md->va */
} uct_cxi_mem_handle_t;


/** Registration cache region; the embedded memh is handed out as uct_mem_h. */
typedef struct uct_cxi_rcache_region {
    ucs_rcache_region_t  super; /**< Base class — must be first */
    uct_cxi_mem_handle_t memh;  /**< Embedded handle exposed as uct_mem_h */
} uct_cxi_rcache_region_t;


/**
 * Packed remote key. The initiator routes by the EP's addresses and
 * addresses memory by {iova, lac}.
 */
/**
 * Remote key. iova is the target's iova_offset, so the initiator computes
 * remote_iova = rkey->iova + remote_addr (IOVAs are private to the target).
 */
/*
 * is_rndv/rendezvous_id: a synthesized rkey for the unexpected-rendezvous
 * pull, which targets the sender's rendezvous source PTE instead of a
 * registered buffer. iova/lac are unused when set; mkey_pack() clears it.
 */
typedef struct uct_cxi_rkey {
    uint64_t iova;          /**< iova_offset = cxi_md->iova - base_VA (see above) */
    uint8_t  lac;           /**< Logical Address Context (memory access class)     */
    uint8_t  is_rndv;       /**< 0 = ordinary RMA rkey (iova/lac valid); 1 =
                                 rendezvous-flavored (rendezvous_id valid) */
    uint8_t  rendezvous_id; /**< Sender's uct_cxi_rdzv_op_t::id -- valid only
                                 when is_rndv is set */
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
