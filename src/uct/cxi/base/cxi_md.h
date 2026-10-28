/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
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
    /* Enable PCIe ATS scalable map */
    ucs_ternary_auto_value_t enable_ats;
    /* Enable registration cache */
    ucs_ternary_auto_value_t enable_rcache;
    /* Registration cache config */
    ucs_rcache_config_t      rcache;
    /* Prefer a dmabuf fd for device memory */
    ucs_ternary_auto_value_t enable_dmabuf;
} uct_cxi_md_config_t;


/** CXI memory domain: the open device and its LNI, shared by all ifaces. */
typedef struct uct_cxi_md {
    /* Must be first */
    uct_md_t         super;
    /* Device descriptor (name, dev_id, nid) */
    uct_cxi_device_t device;
    /* Number of ifaces using this MD */
    int              refcount;
    /* Hardware handles, valid after md_open and released in md_close */
    struct cxil_dev  *cxi_dev;
    /* LNI allocated for svc_id */
    struct cxil_lni  *cxi_lni;
    /* Service ID from SLINGSHOT_SVC_IDS */
    uint32_t         svc_id;
    /* VNI from SLINGSHOT_VNIS */
    uint16_t         vni;
    /* NIC PID width (cxil_dev->info.pid_bits) */
    uint8_t          pid_bits;
    /* Registration cache; NULL if disabled */
    ucs_rcache_t     *rcache;
    /* Scalable ATS mapping; NULL if ATS is disabled */
    struct cxi_md    *ats_md;
    /* Advertise UCT_MD_FLAG_REG_DMABUF */
    int              dmabuf_enabled;
} uct_cxi_md_t;


/**
 * Memory handle from mem_reg. iova_offset (cxi_md->iova - base VA) gives the
 * NIC address of a buffer as iova_offset + buffer VA. In ATS mode it is
 * ats_md->iova (base VA 0).
 */
typedef struct uct_cxi_mem_handle {
    /* Libcxi descriptor; needed for cxil_unmap and for cxi_md->lac in DMA
     * commands */
    struct cxi_md *cxi_md;
    /* cxi_md->iova - cxi_md->va */
    uint64_t      iova_offset;
} uct_cxi_mem_handle_t;

/* NIC address of \a addr within the buffer registered as \a mh. */
static UCS_F_ALWAYS_INLINE uint64_t
uct_cxi_mem_iova(const uct_cxi_mem_handle_t *mh, const void *addr)
{
    return mh->iova_offset + (uint64_t)(uintptr_t)addr;
}


/** Registration cache region; the embedded memh is handed out as uct_mem_h. */
typedef struct uct_cxi_rcache_region {
    /* Must be first */
    ucs_rcache_region_t  super;
    /* Handle exposed as uct_mem_h */
    uct_cxi_mem_handle_t memh;
} uct_cxi_rcache_region_t;


/*
 * Set in the match_bits of a rendezvous Get that the receiver's UCP issues. The
 * Get the NIC issues leaves bits 12..47 clear (struct cxi_rdzv_match_bits in
 * cxi_prov_hw.h), and libfabric marks its software Gets with bit 47 too.
 */
#define UCT_CXI_RDZV_MATCH_SW_PULL UCS_BIT(47)

/**
 * Packed remote key. The initiator routes by the EP's addresses and addresses
 * memory by {iova, lac}. iova is the target's iova_offset, so the initiator
 * computes remote_iova = rkey->iova + remote_addr (IOVAs are private to the
 * target).
 *
 * is_rndv/rendezvous_id: a synthesized rkey for the unexpected-rendezvous
 * pull, which targets the sender's rendezvous source PTE instead of a
 * registered buffer. iova/lac are unused when set; mkey_pack() clears it.
 */
typedef struct uct_cxi_rkey {
    uint64_t iova;
    /* Logical Address Context (memory access class) */
    uint8_t  lac;
    /* 0: ordinary RMA rkey (iova/lac valid); 1: rendezvous (rendezvous_id
     * valid) */
    uint8_t  is_rndv;
    /* Sender's uct_cxi_rdzv_op_t::id */
    uint8_t  rendezvous_id;
} UCS_S_PACKED uct_cxi_rkey_t;


extern uct_component_t uct_cxi_component;

/* Shared registration helpers used by cxi_md.c, cxi_iface.c and cxi_tag.c. */
ucs_status_t uct_cxi_do_map(struct cxil_lni *lni, void *address, size_t length,
                            int dmabuf_fd, size_t dmabuf_offset,
                            ucs_memory_type_t mem_type,
                            uct_cxi_mem_handle_t *mh);
void uct_cxi_do_unmap(uct_cxi_mem_handle_t *mh);

#endif /* UCT_CXI_MD_H */
