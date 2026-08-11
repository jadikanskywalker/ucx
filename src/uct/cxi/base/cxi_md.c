/**
 * CXI memory domain implementation.
 *
 * Modeled on the libfabric CXI provider (cxip_dom.c / cxip_if.c) and the
 * UCX UGNI transport (ugni_md.c) as design references.
 *
 * Lifecycle:
 *   query_md_resources  — enumerate physical CXI devices
 *   md_open             — open device, validate service, alloc LNI
 *   mem_reg             — cxil_map (pin pages, get IOVA + LAC)
 *   mkey_pack           — serialize {iova, lac} for remote peer
 *   mem_dereg           — cxil_unmap
 *   md_close            — destroy LNI, close device
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_md.h"

#include <ucs/debug/log.h>
#include <ucs/sys/compiler.h>
#include <ucs/sys/math.h>
#include <ucs/sys/stubs.h>
#include <ucs/sys/string.h>
#include <ucs/sys/sys.h>
#include <ucs/type/status.h>

#include <ucm/api/ucm.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>


static ucs_config_field_t uct_cxi_md_config_table[] = {
    {"", "", NULL,
     ucs_offsetof(uct_cxi_md_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

    {"ATS", "no",
     "Enable PCIe ATS scalable memory mapping.\n"
     "  yes: require ATS (fail md_open if hardware does not support it)\n"
     "  no:  disable ATS (use pinned registration)\n"
     "  try: use ATS if hardware supports it, fall back silently otherwise\n"
     "Requires AMD IOMMU enabled in the kernel; defaults to no on COSMOS.",
     ucs_offsetof(uct_cxi_md_config_t, enable_ats),
     UCS_CONFIG_TYPE_TERNARY},

    {"RCACHE", "try",
     "Enable memory registration cache.\n"
     "  yes: require cache (fail md_open if unavailable)\n"
     "  no:  disable cache (every mem_reg calls cxil_map directly)\n"
     "  try: enable if possible, fall back silently otherwise",
     ucs_offsetof(uct_cxi_md_config_t, enable_rcache),
     UCS_CONFIG_TYPE_TERNARY},

    {"", "", NULL,
     ucs_offsetof(uct_cxi_md_config_t, rcache),
     UCS_CONFIG_TYPE_TABLE(ucs_config_rcache_table)},

    {NULL}
};


/* -------------------------------------------------------------------------
 * Credential helpers — mirror cxip_nic.c logic from libfabric CXI provider
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_get_svc_id - read SLINGSHOT_SVC_IDS and return the entry for a
 * given device index (cxi0 → index 0, cxi1 → index 1, ...).
 *
 * SLINGSHOT_SVC_IDS is a comma-separated list; the SLURM plugin sets one
 * entry per NIC, e.g. "4,4,4,4" for four NICs all using service 4.
 *
 * Returns the svc_id on success, or -1 if the variable is absent or the
 * index is out of range.
 */
static int uct_cxi_get_svc_id(unsigned dev_id)
{
    char *env = getenv("SLINGSHOT_SVC_IDS");
    char *dup;
    char *token;
    int   svc_id = -1;
    unsigned idx = 0;

    if (env == NULL) {
        return -1;
    }

    dup = strdup(env);
    if (dup == NULL) {
        return -1;
    }

    for (token = strtok(dup, ","); token != NULL;
         token = strtok(NULL, ","), idx++) {
        if (idx == dev_id) {
            svc_id = atoi(token);
            break;
        }
    }

    free(dup);

    if (svc_id < 0) {
        ucs_warn("SLINGSHOT_SVC_IDS has no entry for device index %u "
                 "(value: %s)", dev_id, env);
    }

    return svc_id;
}

/*
 * uct_cxi_get_vni - read SLINGSHOT_VNIS and return the first VNI token.
 *
 * Returns the VNI on success, or 0 if the variable is absent or unparseable.
 */
static uint16_t uct_cxi_get_vni(void)
{
    char *env = getenv("SLINGSHOT_VNIS");
    char *dup;
    char *token;
    uint16_t vni = 0;

    if (env == NULL) {
        return 0;
    }

    dup = strdup(env);
    if (dup == NULL) {
        return 0;
    }

    token = strtok(dup, ",");
    if (token != NULL) {
        vni = (uint16_t)atoi(token);
    }

    free(dup);
    return vni;
}

/*
 * uct_cxi_log_svc_desc - dump one service descriptor's full detail (id,
 * enable/system/restriction flags, every UID/GID member, every VNI) at
 * trace verbosity. Called for every entry regardless of whether it ends up
 * selected, so a cluster's raw service configuration (including
 * disabled/system services) is visible with UCX_LOG_LEVEL=trace without
 * needing external tooling.
 */
static void uct_cxi_log_svc_desc(int idx, const struct cxi_svc_desc *desc)
{
    unsigned k;
    int      j;

    ucs_trace("cxi svc[%d] id %u enable %d system %d restricted_members %d "
              "restricted_vnis %d num_vld_vnis %d",
              idx, desc->svc_id, desc->enable, desc->is_system_svc,
              desc->restricted_members, desc->restricted_vnis,
              desc->num_vld_vnis);

    if (desc->restricted_members) {
        for (j = 0; j < CXI_SVC_MAX_MEMBERS; j++) {
            if (desc->members[j].type == CXI_SVC_MEMBER_UID) {
                ucs_trace("cxi svc[%d] member[%d] uid %u", idx, j,
                          (unsigned)desc->members[j].svc_member.uid);
            } else if (desc->members[j].type == CXI_SVC_MEMBER_GID) {
                ucs_trace("cxi svc[%d] member[%d] gid %u", idx, j,
                          (unsigned)desc->members[j].svc_member.gid);
            }
        }
    }

    if (desc->restricted_vnis) {
        for (k = 0; k < desc->num_vld_vnis; k++) {
            ucs_trace("cxi svc[%d] vni[%u] %u", idx, k,
                      (unsigned)desc->vnis[k]);
        }
    }
}

/*
 * uct_cxi_find_svc_by_membership - fall back to kernel-side service
 * discovery when the launcher does not export SLINGSHOT_SVC_IDS /
 * SLINGSHOT_DEVICES / SLINGSHOT_VNIS.
 *
 * Mirrors libfabric's CXI provider (cxip_nic_get_best_rgroup_vni in
 * prov/cxi/src/cxip_nic.c): scan the device's pre-configured services via
 * cxil_get_svc_list() and pick, in priority order, the first enabled
 * non-system service that is (a) restricted to our effective UID,
 * (b) restricted to our effective GID, or (c) unrestricted.
 *
 * On success returns the chosen service ID and fills *vni_p (from the
 * service's own VNI restriction, or 0 if the service does not restrict
 * VNIs — the caller decides what to do with an unrestricted VNI).  Returns
 * -1 if no usable service is found.
 */
static int uct_cxi_find_svc_by_membership(struct cxil_dev *dev, uint16_t *vni_p)
{
    struct cxil_svc_list *svc_list;
    struct cxi_svc_desc  *desc;
    uid_t                 uid = geteuid();
    gid_t                 gid = getegid();
    int                   found_uid = -1;
    int                   found_gid = -1;
    int                   found_unrestricted = -1;
    int                   i, j;
    int                   ret;

    ret = cxil_get_svc_list(dev, &svc_list);
    if (ret != 0) {
        ucs_debug("cxi cxil_get_svc_list failed: %s", strerror(-ret));
        return -1;
    }

    ucs_debug("cxi %s: querying service list (%u entries, euid %d egid %d)",
              dev->info.device_name, svc_list->count, (int)uid, (int)gid);

    /* Priority: UID match, then GID match, then unrestricted. Walk the list
     * back-to-front and lock in the first (i.e. highest-index) match for
     * each category — matches cxip_nic_get_best_rgroup_vni exactly, so a
     * process sees the same service UCX and libfabric/MPI would agree on. */
    for (i = (int)svc_list->count - 1; i >= 0; i--) {
        desc = svc_list->descs + i;

        if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE)) {
            uct_cxi_log_svc_desc(i, desc);
        }

        if (!desc->enable || desc->is_system_svc) {
            continue;
        }

        if (!desc->restricted_members) {
            if (found_unrestricted == -1) {
                found_unrestricted = i;
            }
            continue;
        }

        for (j = 0; j < CXI_SVC_MAX_MEMBERS; j++) {
            if ((desc->members[j].type == CXI_SVC_MEMBER_UID) &&
                (desc->members[j].svc_member.uid == uid) &&
                (found_uid == -1)) {
                found_uid = i;
            } else if ((desc->members[j].type == CXI_SVC_MEMBER_GID) &&
                       (desc->members[j].svc_member.gid == gid) &&
                       (found_gid == -1)) {
                found_gid = i;
            }
        }
    }

    if (found_uid != -1) {
        i = found_uid;
    } else if (found_gid != -1) {
        i = found_gid;
    } else if (found_unrestricted != -1) {
        i = found_unrestricted;
    } else {
        ucs_debug("cxi no service matches uid %d gid %d and no unrestricted "
                  "service is available", (int)uid, (int)gid);
        cxil_free_svc_list(svc_list);
        return -1;
    }

    desc = svc_list->descs + i;

    if (desc->restricted_vnis && (desc->num_vld_vnis > 0)) {
        *vni_p = (uint16_t)desc->vnis[0];
    } else {
        *vni_p = 0;
    }

    i = (int)desc->svc_id;

    ucs_debug("cxi found svc_id %d vni %u via service membership "
              "(uid %d gid %d)", i, (unsigned)*vni_p, (int)uid, (int)gid);

    cxil_free_svc_list(svc_list);
    return i;
}

/*
 * uct_cxi_get_rgroup_vni - resolve the (service ID, VNI) pair used to open
 * this device.  Two paths, tried in order (mirrors libfabric's CXI
 * provider: cxip_nic_get_rgroup_vni in prov/cxi/src/cxip_nic.c):
 *
 *  1. SLINGSHOT_SVC_IDS / SLINGSHOT_DEVICES / SLINGSHOT_VNIS, set by a
 *     Slingshot-aware launcher (e.g. the SLURM plugin).  Preferred when
 *     present, since it reflects what the WLM actually granted this job
 *     step.
 *  2. Kernel-side service discovery (uct_cxi_find_svc_by_membership) when
 *     the launcher does not export those variables.
 *
 * Returns UCS_OK with *svc_id_p/*vni_p filled, or UCS_ERR_NO_DEVICE if
 * neither path found a usable service.
 */
static ucs_status_t uct_cxi_get_rgroup_vni(struct cxil_dev *dev,
                                           unsigned dev_id, int *svc_id_p,
                                           uint16_t *vni_p)
{
    int      svc_id;
    uint16_t vni;

    svc_id = uct_cxi_get_svc_id(dev_id);
    vni    = uct_cxi_get_vni();
    if ((svc_id >= 0) && (vni != 0)) {
        ucs_debug("cxi resolved svc_id %d vni %u from SLINGSHOT_* env",
                  svc_id, (unsigned)vni);
        *svc_id_p = svc_id;
        *vni_p    = vni;
        return UCS_OK;
    }

    ucs_debug("cxi SLINGSHOT_* env incomplete (svc_id %d vni %u), falling "
              "back to service membership lookup", svc_id, (unsigned)vni);

    svc_id = uct_cxi_find_svc_by_membership(dev, &vni);
    if (svc_id < 0) {
        return UCS_ERR_NO_DEVICE;
    }

    *svc_id_p = svc_id;
    *vni_p    = vni;
    return UCS_OK;
}

/*
 * uct_cxi_devname_to_id - convert "cxiN" to the numeric device index N.
 * Returns -1 if the name does not match the expected pattern.
 */
static int uct_cxi_devname_to_id(const char *name)
{
    unsigned id;

    if (sscanf(name, "cxi%u", &id) != 1) {
        return -1;
    }

    return (int)id;
}


/* -------------------------------------------------------------------------
 * query_md_resources
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_query_md_resources - enumerate CXI devices available to this job.
 *
 * Advertises one MD resource per physical CXI device found by
 * cxil_get_device_list(), with no credential check here: whether this
 * process can actually use a device (SLINGSHOT_* env vars, or a
 * pre-configured service matching our uid/gid, or an unrestricted service —
 * see uct_cxi_get_rgroup_vni) is resolved per-device in md_open, same as
 * e.g. IB pkey access. This lets md_open's service-membership fallback run
 * on launchers that don't export SLINGSHOT_SVC_IDS; a device with no usable
 * service simply fails md_open and UCX skips it.
 */
ucs_status_t uct_cxi_query_md_resources(uct_component_h component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p)
{
    struct cxil_device_list *dev_list = NULL;
    uct_md_resource_desc_t  *resources;
    unsigned int             i;
    int                      ret;

    ret = cxil_get_device_list(&dev_list);
    if (ret != 0) {
        ucs_error("cxil_get_device_list failed: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    if (dev_list->count == 0) {
        ucs_debug("cxi no CXI devices found");
        cxil_free_device_list(dev_list);
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    resources = ucs_calloc(dev_list->count, sizeof(*resources), "cxi md resources");
    if (resources == NULL) {
        cxil_free_device_list(dev_list);
        return UCS_ERR_NO_MEMORY;
    }

    ucs_debug("cxi found %u CXI device(s)", dev_list->count);

    for (i = 0; i < dev_list->count; i++) {
        ucs_strncpy_safe(resources[i].md_name,
                         dev_list->info[i].device_name,
                         sizeof(resources[i].md_name));
        ucs_debug("cxi device %u name %s nid 0x%x",
                  i, dev_list->info[i].device_name,
                  dev_list->info[i].nid);
    }

    cxil_free_device_list(dev_list);

    *resources_p     = resources;
    *num_resources_p = i;
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * md_query — advertise memory domain capabilities
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_md_query(uct_md_h md, uct_md_attr_v2_t *md_attr)
{
    uct_md_base_md_query(md_attr);
    md_attr->flags            = UCT_MD_FLAG_REG | UCT_MD_FLAG_NEED_MEMH |
                                UCT_MD_FLAG_NEED_RKEY;
    md_attr->reg_mem_types    = UCS_BIT(UCS_MEMORY_TYPE_HOST);
    md_attr->access_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
    md_attr->cache_mem_types  = UCS_BIT(UCS_MEMORY_TYPE_HOST);
    md_attr->detect_mem_types = 0;
    md_attr->dmabuf_mem_types = 0;
    md_attr->rkey_packed_size = sizeof(uct_cxi_rkey_t);
    md_attr->reg_cost         = ucs_linear_func_make(1000.0e-9, 0.007e-9);
    return UCS_OK;
}


void uct_cxi_md_close(uct_md_h mdh)
{
    uct_cxi_md_t *md = ucs_derived_of(mdh, uct_cxi_md_t);
    int           ret;

    ucs_debug("cxi md close device %s lni_id %u",
              md->device.name, md->cxi_lni->id);

    /* Release ATS scalable mapping before the LNI (cxil_unmap needs live LNI). */
    if (md->ats_md != NULL) {
        ret = cxil_unmap(md->ats_md);
        if (ret != 0) {
            ucs_warn("cxi ATS cxil_unmap failed: %s", strerror(-ret));
        }
    }

    /* Destroy the rcache before the LNI: the eviction callback calls
     * cxil_unmap, which requires a live LNI handle. */
    if (md->rcache != NULL) {
        ucs_rcache_destroy(md->rcache);
    }

    ret = cxil_destroy_lni(md->cxi_lni);
    if (ret != 0) {
        ucs_warn("cxil_destroy_lni failed: %s", strerror(-ret));
    }

    cxil_close_device(md->cxi_dev);
    uct_cxi_device_cleanup(&md->device);
    ucs_free(md);
}


/* -------------------------------------------------------------------------
 * mem_reg / mem_dereg — host memory registration via cxil_map
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_do_map - call cxil_map and fill a mem handle.
 *
 * Shared by the direct registration path (uct_cxi_md_mem_reg) and the
 * rcache miss callback (uct_cxi_rcache_mem_reg_cb).  Both paths produce a
 * uct_cxi_mem_handle_t with a valid cxi_md; only the allocation strategy
 * differs (ucs_malloc vs embedded in the rcache region).
 *
 * cxil_map() pins the pages, programs the NIC's ATU, and fills cxi_md with:
 *   .iova  — page-aligned NIC-visible base address of the registration
 *   .va    — page-aligned virtual address base of the registration
 *   .lac   — memory access class (shared across all same-page-size mappings)
 *   .len   — page-aligned length of the mapping
 *
 * Both .iova and .va are page-aligned — they correspond to the page start,
 * not the exact buffer pointer passed to cxil_map.
 *
 * CXI_MAP_PIN ensures physical page pinning (required for DMA).
 * CXI_MAP_READ | CXI_MAP_WRITE grants bidirectional NIC access.
 */
ucs_status_t uct_cxi_do_map(struct cxil_lni *lni, void *address,
                                   size_t length, uct_cxi_mem_handle_t *mh)
{
    int flags = CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE;
    int ret;

    ret = cxil_map(lni, address, length, flags, NULL, &mh->cxi_md);
    if (ret != 0) {
        ucs_error("cxi cxil_map lni_id %u addr %p len %zu failed: %s",
                  lni->id, address, length, strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    /*
     * Precompute iova_offset = page_IOVA - page_VA.
     *
     * For any buffer VA within this registration:
     *   NIC_IOVA(buf) = iova_offset + buf_VA
     *               = (page_IOVA - page_VA) + buf_VA
     *               = page_IOVA + (buf_VA - page_VA)
     *
     * Using cxi_md->va (the page-aligned VA) instead of the raw `address`
     * parameter is critical: `address` may be non-page-aligned, which would
     * cause `iova_offset + buf_VA` to resolve to `page_IOVA` (page start)
     * rather than the correct per-byte IOVA.
     */
    mh->iova_offset = mh->cxi_md->iova - mh->cxi_md->va;

    ucs_debug("cxi map addr %p len %zu iova 0x%"PRIx64" lac %u offset 0x%"PRIx64,
              address, length, (uint64_t)mh->cxi_md->iova,
              (unsigned)mh->cxi_md->lac, mh->iova_offset);
    return UCS_OK;
}

/* Counterpart to uct_cxi_do_map — shared by direct, rcache, and iface paths. */
void uct_cxi_do_unmap(uct_cxi_mem_handle_t *mh)
{
    int ret = cxil_unmap(mh->cxi_md);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap failed: %s", strerror(-ret));
    }
}

/* Direct (non-cached) path: allocate a handle, call cxil_map. */
static ucs_status_t uct_cxi_md_mem_reg(uct_md_h mdh, void *address,
                                       size_t length,
                                       const uct_md_mem_reg_params_t *params,
                                       uct_mem_h *memh_p)
{
    uct_cxi_md_t         *md = ucs_derived_of(mdh, uct_cxi_md_t);
    uct_cxi_mem_handle_t *mh;
    ucs_status_t          status;

    mh = ucs_malloc(sizeof(*mh), "uct_cxi_mem_handle");
    if (mh == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    status = uct_cxi_do_map(md->cxi_lni, address, length, mh);
    if (status != UCS_OK) {
        ucs_free(mh);
        return status;
    }

    *memh_p = mh;
    return UCS_OK;
}

/* Direct (non-cached) path: call cxil_unmap and free the handle. */
static ucs_status_t
uct_cxi_md_mem_dereg(uct_md_h mdh, const uct_md_mem_dereg_params_t *params)
{
    uct_cxi_mem_handle_t *mh = params->memh;

    UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);
    uct_cxi_do_unmap(mh);
    ucs_free(mh);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * Registration cache — callbacks, ops table, user-facing wrappers
 * -------------------------------------------------------------------------
 */

/*
 * Cache miss: the rcache calls this to create a new entry for a VA range it
 * has not seen before.  The region struct is already allocated by the rcache;
 * we only need to fill region->memh via cxil_map.  The rcache uses the
 * page-aligned (start, end) rather than the caller's original (va, len) so
 * that overlapping requests can share a single underlying mapping.
 */
static ucs_status_t
uct_cxi_rcache_mem_reg_cb(void *context, ucs_rcache_t *rcache,
                          void *arg, ucs_rcache_region_t *rregion,
                          uint16_t rcache_mem_reg_flags)
{
    uct_cxi_md_t            *md     = context;
    uct_cxi_rcache_region_t *region = ucs_derived_of(rregion,
                                                     uct_cxi_rcache_region_t);

    return uct_cxi_do_map(md->cxi_lni,
                          (void *)rregion->super.start,
                          rregion->super.end - rregion->super.start,
                          &region->memh);
}

/*
 * Cache eviction: called when the region's refcount drops to zero and the
 * entry is removed from the page table.  Must release the cxil mapping
 * before the region struct is freed by the rcache.
 */
static void
uct_cxi_rcache_mem_dereg_cb(void *context, ucs_rcache_t *rcache,
                            ucs_rcache_region_t *rregion)
{
    uct_cxi_rcache_region_t *region = ucs_derived_of(rregion,
                                                     uct_cxi_rcache_region_t);
    uct_cxi_do_unmap(&region->memh);
}

static void
uct_cxi_rcache_dump_region_cb(void *context, ucs_rcache_t *rcache,
                              ucs_rcache_region_t *rregion, char *buf,
                              size_t max)
{
    uct_cxi_rcache_region_t *region = ucs_derived_of(rregion,
                                                     uct_cxi_rcache_region_t);
    snprintf(buf, max, "iova 0x%"PRIx64" lac %u",
             (uint64_t)region->memh.cxi_md->iova,
             (unsigned)region->memh.cxi_md->lac);
}

static ucs_rcache_ops_t uct_cxi_rcache_ops = {
    .mem_reg     = uct_cxi_rcache_mem_reg_cb,
    .mem_dereg   = uct_cxi_rcache_mem_dereg_cb,
    .merge       = (void *)ucs_empty_function,
    .dump_region = uct_cxi_rcache_dump_region_cb
};

/*
 * Cached mem_reg: look up (or create) a cache entry for the requested range.
 * On a cache hit the reference count of the existing region is incremented and
 * no cxil_map call is made.  The returned uct_mem_h points directly into the
 * region struct and is valid as long as the caller holds its reference.
 */
static ucs_status_t
uct_cxi_md_mem_rcache_reg(uct_md_h uct_md, void *address, size_t length,
                          const uct_md_mem_reg_params_t *params,
                          uct_mem_h *memh_p)
{
    uct_cxi_md_t        *md = ucs_derived_of(uct_md, uct_cxi_md_t);
    ucs_rcache_region_t *rregion;
    ucs_status_t         status;

    status = ucs_rcache_get(md->rcache, address, length,
                            ucs_get_page_size(), PROT_READ | PROT_WRITE,
                            NULL, &rregion);
    if (status != UCS_OK) {
        return status;
    }

    ucs_assert(rregion->refcount > 0);
    *memh_p = &ucs_derived_of(rregion, uct_cxi_rcache_region_t)->memh;
    return UCS_OK;
}

/*
 * Cached mem_dereg: release the caller's reference.  The cxil_unmap is
 * deferred until all references (user + cache's own page-table entry) are
 * dropped, at which point the rcache calls uct_cxi_rcache_mem_dereg_cb.
 */
static ucs_status_t
uct_cxi_md_mem_rcache_dereg(uct_md_h uct_md,
                            const uct_md_mem_dereg_params_t *params)
{
    uct_cxi_md_t            *md     = ucs_derived_of(uct_md, uct_cxi_md_t);
    uct_cxi_mem_handle_t    *mh     = params->memh;
    uct_cxi_rcache_region_t *region;

    UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);

    region = ucs_container_of(mh, uct_cxi_rcache_region_t, memh);
    ucs_rcache_region_put(md->rcache, &region->super);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * mkey_pack / rkey_unpack — remote key serialization
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_md_mkey_pack - serialize the memory descriptor for restricted-mode
 * DMA.
 *
 * The initiator EP has the peer's {nid, pid, ptn} from device_addr and
 * iface_addr already; it needs only the memory-access fields from the rkey:
 *   iova  — iova_offset = cxi_md->iova - base_VA; lets ep_put_zcopy compute
 *            remote_iova = rkey->iova + remote_addr with a single addition
 *   lac   — Logical Address Context (page-table slot assigned by cxil_map)
 */
static ucs_status_t
uct_cxi_md_mkey_pack(uct_md_h mdh, uct_mem_h memh, void *address,
                     size_t length, const uct_md_mkey_pack_params_t *params,
                     void *mkey_buffer)
{
    uct_cxi_mem_handle_t  *mh   = memh;
    uct_cxi_rkey_t        *rkey = mkey_buffer;

    rkey->iova = mh->iova_offset;  /* = cxi_md->iova - base_VA */
    rkey->lac  = mh->cxi_md->lac;

    ucs_debug("cxi mkey pack iova_offset 0x%"PRIx64" lac %u",
              rkey->iova, (unsigned)rkey->lac);
    return UCS_OK;
}

static ucs_status_t uct_cxi_rkey_unpack(uct_component_h component,
                                        const void *rkey_buffer,
                                        const uct_rkey_unpack_params_t *params,
                                        uct_rkey_t *rkey_p, void **handle_p)
{
    uct_cxi_rkey_t *src  = (uct_cxi_rkey_t *)rkey_buffer;
    uct_cxi_rkey_t *rkey = ucs_malloc(sizeof(*rkey), "uct_cxi_rkey");

    if (rkey == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    *rkey    = *src;
    *rkey_p  = (uct_rkey_t)(uintptr_t)rkey;
    *handle_p = NULL;

    ucs_debug("cxi rkey unpack iova 0x%"PRIx64" lac %u",
              rkey->iova, (unsigned)rkey->lac);
    return UCS_OK;
}

static ucs_status_t uct_cxi_rkey_release(uct_component_h component,
                                         uct_rkey_t rkey, void *handle)
{
    ucs_free((void *)(uintptr_t)rkey);
    return UCS_OK;
}

static ucs_status_t uct_cxi_md_mem_query(uct_md_h md, const void *address,
                                         size_t length,
                                         uct_md_mem_attr_v2_t *attr)
{
    return UCS_ERR_UNSUPPORTED;
}

static ucs_status_t
uct_cxi_md_detect_memory_type(uct_md_h md, const void *address, size_t length,
                              ucs_memory_type_t *mem_type_p)
{
    return UCS_ERR_UNSUPPORTED;
}


/* -------------------------------------------------------------------------
 * ATS (PCIe Address Translation Services) — capability probe, scalable
 * init, and ops callbacks.
 *
 * ATS mode uses a single cxil_map over the full 48-bit VA space
 * (CXI_MAP_ATS, no CXI_MAP_PIN).  The NIC translates VAs on-demand via
 * the host IOMMU rather than pinning pages at registration time.
 *
 * Modeled on cxip_ats_check() and cxip_scalable_iomm_init() in
 * libfabric's cxip_iomm.c.
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ats_check - probe whether this LNI's hardware supports ATS.
 *
 * Attempts to map a small stack variable with CXI_MAP_ATS|CXI_MAP_PIN
 * (the probe flags used by libfabric).  A successful map + immediate unmap
 * confirms ATS is available; failure means the kernel or firmware does not
 * support it (returns 0 in that case).
 */
static int uct_cxi_ats_check(struct cxil_lni *lni)
{
    int            stack_var;
    struct cxi_md *md;
    int            ret;

    ret = cxil_map(lni, &stack_var, sizeof(stack_var),
                   CXI_MAP_READ | CXI_MAP_WRITE | CXI_MAP_ATS | CXI_MAP_PIN,
                   NULL, &md);
    if (ret != 0) {
        ucs_debug("cxi PCIe ATS not supported: %s", strerror(-ret));
        return 0;
    }

    cxil_unmap(md);
    ucs_debug("cxi PCIe ATS supported");
    return 1;
}

/*
 * uct_cxi_ats_init - create the full-VA-space scalable ATS mapping.
 *
 * Maps VA 0 to 0xfffffffffffff000 with CXI_MAP_ATS (no CXI_MAP_PIN).
 * The resulting cxi_md carries a single LAC valid for every buffer.
 * Because the map starts at VA 0, iova_offset = ats_md->iova (base_VA = 0),
 * so ep_put_zcopy computes local_iova = ats_md->iova + buffer_VA uniformly.
 */
static ucs_status_t uct_cxi_ats_init(uct_cxi_md_t *md)
{
    int ret;

    ret = cxil_map(md->cxi_lni, 0, 0xfffffffffffff000,
                   CXI_MAP_READ | CXI_MAP_WRITE | CXI_MAP_ATS,
                   NULL, &md->ats_md);
    if (ret != 0) {
        ucs_error("cxi ATS scalable map failed: %s", strerror(-ret));
        md->ats_md = NULL;
        return UCS_ERR_IO_ERROR;
    }

    ucs_debug("cxi ATS scalable map iova 0x%"PRIx64" lac %u",
              (uint64_t)md->ats_md->iova, (unsigned)md->ats_md->lac);
    return UCS_OK;
}

/*
 * ATS mem_reg: the scalable mapping covers every VA in the process.
 * Allocate a real uct_cxi_mem_handle_t so that ep_put_zcopy can access
 * iova_offset and lac uniformly regardless of ATS vs pinned mode.
 * iova_offset = ats_md->iova because the map starts at VA 0 (base_VA = 0).
 */
static ucs_status_t
uct_cxi_md_mem_ats_reg(uct_md_h mdh, void *address, size_t length,
                       const uct_md_mem_reg_params_t *params,
                       uct_mem_h *memh_p)
{
    uct_cxi_md_t         *md = ucs_derived_of(mdh, uct_cxi_md_t);
    uct_cxi_mem_handle_t *mh;

    mh = ucs_malloc(sizeof(*mh), "uct_cxi_ats_memh");
    if (mh == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    mh->cxi_md      = md->ats_md;
    /* ATS maps from VA 0, so cxi_md->va = 0 and
     * iova_offset = page_IOVA - page_VA = ats_md->iova - 0 = ats_md->iova. */
    mh->iova_offset = (uint64_t)md->ats_md->iova;

    *memh_p = mh;
    return UCS_OK;
}

/* ATS mem_dereg: free the per-registration handle (no cxil_unmap needed). */
static ucs_status_t
uct_cxi_md_mem_ats_dereg(uct_md_h mdh,
                         const uct_md_mem_dereg_params_t *params)
{
    UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);
    ucs_free(params->memh);
    return UCS_OK;
}

/*
 * ATS mkey_pack: iova_offset = ats_md->iova (base_VA = 0), so the initiator
 * computes remote_iova = rkey->iova + remote_addr — same formula as pinned.
 */
static ucs_status_t
uct_cxi_md_mkey_pack_ats(uct_md_h mdh, uct_mem_h memh, void *address,
                         size_t length,
                         const uct_md_mkey_pack_params_t *params,
                         void *mkey_buffer)
{
    uct_cxi_mem_handle_t *mh   = memh;
    uct_cxi_rkey_t       *rkey = mkey_buffer;

    rkey->iova = mh->iova_offset;  /* = ats_md->iova */
    rkey->lac  = mh->cxi_md->lac;

    ucs_debug("cxi ATS mkey pack iova_offset 0x%"PRIx64" lac %u",
              rkey->iova, (unsigned)rkey->lac);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * ops table and md_open — after all static functions they reference
 * -------------------------------------------------------------------------
 */

static uct_md_ops_t uct_cxi_md_ops = {
    .close              = uct_cxi_md_close,
    .query              = uct_cxi_md_query,
    .mem_alloc          = (uct_md_mem_alloc_func_t)ucs_empty_function_return_unsupported,
    .mem_free           = (uct_md_mem_free_func_t)ucs_empty_function_return_unsupported,
    .mem_advise         = (uct_md_mem_advise_func_t)ucs_empty_function_return_unsupported,
    .mem_reg            = uct_cxi_md_mem_reg,
    .mem_dereg          = uct_cxi_md_mem_dereg,
    .mem_query          = uct_cxi_md_mem_query,
    .mkey_pack          = uct_cxi_md_mkey_pack,
    .mem_attach         = (uct_md_mem_attach_func_t)ucs_empty_function_return_unsupported,
    .detect_memory_type = uct_cxi_md_detect_memory_type
};

/* ATS variant — mem_reg/mem_dereg are no-ops; mkey_pack uses VA arithmetic. */
static uct_md_ops_t uct_cxi_md_ats_ops = {
    .close              = uct_cxi_md_close,
    .query              = uct_cxi_md_query,
    .mem_alloc          = (uct_md_mem_alloc_func_t)ucs_empty_function_return_unsupported,
    .mem_free           = (uct_md_mem_free_func_t)ucs_empty_function_return_unsupported,
    .mem_advise         = (uct_md_mem_advise_func_t)ucs_empty_function_return_unsupported,
    .mem_reg            = uct_cxi_md_mem_ats_reg,
    .mem_dereg          = uct_cxi_md_mem_ats_dereg,
    .mem_query          = uct_cxi_md_mem_query,
    .mkey_pack          = uct_cxi_md_mkey_pack_ats,
    .mem_attach         = (uct_md_mem_attach_func_t)ucs_empty_function_return_unsupported,
    .detect_memory_type = uct_cxi_md_detect_memory_type
};

/* Registration-cached variant — identical except for mem_reg / mem_dereg. */
static uct_md_ops_t uct_cxi_md_rcache_ops = {
    .close              = uct_cxi_md_close,
    .query              = uct_cxi_md_query,
    .mem_alloc          = (uct_md_mem_alloc_func_t)ucs_empty_function_return_unsupported,
    .mem_free           = (uct_md_mem_free_func_t)ucs_empty_function_return_unsupported,
    .mem_advise         = (uct_md_mem_advise_func_t)ucs_empty_function_return_unsupported,
    .mem_reg            = uct_cxi_md_mem_rcache_reg,
    .mem_dereg          = uct_cxi_md_mem_rcache_dereg,
    .mem_query          = uct_cxi_md_mem_query,
    .mkey_pack          = uct_cxi_md_mkey_pack,
    .mem_attach         = (uct_md_mem_attach_func_t)ucs_empty_function_return_unsupported,
    .detect_memory_type = uct_cxi_md_detect_memory_type
};

ucs_status_t uct_cxi_md_open(uct_component_h component, const char *md_name,
                             const uct_md_config_t *md_config, uct_md_h *md_p)
{
    const uct_cxi_md_config_t *cfg = ucs_derived_of(md_config,
                                                    uct_cxi_md_config_t);
    struct cxi_svc_desc  svc_desc = {};
    ucs_rcache_params_t  rcache_params;
    uct_cxi_md_t        *md;
    uint32_t             nid    = 0;
    uint32_t             dev_id = 0;
    int                  svc_id;
    uint16_t             vni;
    int                  ret;
    ucs_status_t         status;

    /* Translate "cxiN" name to numeric device index. */
    ret = uct_cxi_devname_to_id(md_name);
    if (ret < 0) {
        ucs_error("cxi invalid device name %s", md_name);
        return UCS_ERR_INVALID_PARAM;
    }

    dev_id = (uint32_t)ret;

    md = ucs_malloc(sizeof(*md), "uct_cxi_md");
    if (md == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    /* Open the CXI device.  cxil_open_device takes the numeric device ID. */
    ret = cxil_open_device(dev_id, &md->cxi_dev);
    if (ret != 0) {
        ucs_error("cxil_open_device dev_id %u failed: %s",
                  dev_id, strerror(-ret));
        status = UCS_ERR_NO_DEVICE;
        goto err_free_md;
    }

    nid = md->cxi_dev->info.nid;

    /*
     * Resolve which service ID / VNI to open this device with: prefer
     * SLINGSHOT_* env vars injected by the launcher, else fall back to
     * kernel-side service-membership discovery. See uct_cxi_get_rgroup_vni.
     */
    status = uct_cxi_get_rgroup_vni(md->cxi_dev, dev_id, &svc_id, &vni);
    if (status != UCS_OK) {
        ucs_error("cxi no usable service found for device %s (dev_id %u): "
                  "checked SLINGSHOT_SVC_IDS/SLINGSHOT_DEVICES/"
                  "SLINGSHOT_VNIS and pre-configured service membership "
                  "(uid/gid/unrestricted)", md_name, dev_id);
        goto err_close_dev;
    }

    ucs_debug("cxi opening device %s dev_id %u svc_id %d vni %u",
              md_name, dev_id, svc_id, (unsigned)vni);

    /*
     * Validate the service: cxil_get_svc ensures the svc_id is known to the
     * kernel and lets us read per-service resource limits (e.g. max TLEs).
     * An absent or disabled service means the SLURM plugin didn't grant
     * access — fail fast rather than hitting EKEYREVOKED on alloc_lni.
     */
    ret = cxil_get_svc(md->cxi_dev, (unsigned)svc_id, &svc_desc);
    if (ret != 0) {
        ucs_error("cxil_get_svc dev %s svc_id %d failed: %s",
                  md_name, svc_id, strerror(-ret));
        status = UCS_ERR_NO_DEVICE;
        goto err_close_dev;
    }

    if (!svc_desc.enable) {
        ucs_error("cxi service %d on device %s is not enabled", svc_id,
                  md_name);
        status = UCS_ERR_NO_DEVICE;
        goto err_close_dev;
    }

    /*
     * Allocate the LNI.  This is the authorization gate: the kernel checks
     * the process's keyring credential (set by SLURM plugin) and returns
     * EKEYREVOKED if the credential is absent or mismatched.  All subsequent
     * resources (CMDQs, EVTQs, PTEs, memory maps) hang off this LNI.
     */
    ret = cxil_alloc_lni(md->cxi_dev, &md->cxi_lni, (unsigned)svc_id);
    if (ret != 0) {
        ucs_error("cxil_alloc_lni dev %s svc_id %d failed: %s",
                  md_name, svc_id, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_close_dev;
    }

    /* Fill UCT MD fields. */
    status = uct_cxi_device_init(&md->device, md_name, dev_id, nid);
    if (status != UCS_OK) {
        goto err_destroy_lni;
    }

    md->super.ops       = &uct_cxi_md_ops;
    md->super.component = component;
    md->refcount        = 1;
    md->svc_id          = (uint32_t)svc_id;
    md->vni             = vni;
    md->pid_bits        = (uint8_t)md->cxi_dev->info.pid_bits;
    md->rcache          = NULL;
    md->ats_md          = NULL;

    /*
     * Optionally enable PCIe ATS scalable mapping.  ATS replaces per-buffer
     * pinning with a single full-VA-space cxil_map; mem_reg becomes a no-op
     * and IOVA is computed as ats_md->iova + VA at mkey_pack time.
     *
     * ATS takes priority over the rcache: if ATS is active there are no
     * cxil_map calls per registration, so the cache would be pointless.
     *
     * Must be set up BEFORE uct_md_vfs_init and destroyed BEFORE the LNI.
     */
    if (cfg->enable_ats != UCS_NO) {
        if (uct_cxi_ats_check(md->cxi_lni)) {
            status = uct_cxi_ats_init(md);
            if (status == UCS_OK) {
                md->super.ops = &uct_cxi_md_ats_ops;
                ucs_debug("cxi ATS enabled for %s", md_name);
            } else if (cfg->enable_ats == UCS_YES) {
                ucs_error("cxi ATS required but scalable map failed for %s",
                          md_name);
                goto err_destroy_lni;
            } else {
                ucs_debug("cxi ATS scalable map failed for %s (%s), "
                          "falling back to pinned registration",
                          md_name, ucs_status_string(status));
            }
        } else if (cfg->enable_ats == UCS_YES) {
            ucs_error("cxi ATS required but hardware does not support it: %s",
                      md_name);
            status = UCS_ERR_UNSUPPORTED;
            goto err_destroy_lni;
        }
    }

    /*
     * Optionally create a registration cache (skipped when ATS is active).
     * The cache eliminates repeated cxil_map/cxil_unmap calls for overlapping
     * VA ranges.  When active, md->super.ops is replaced with the rcache
     * variant.
     *
     * The rcache must be created BEFORE uct_md_vfs_init so that the VFS
     * node can inspect rcache stats if desired.  It must be destroyed
     * BEFORE the LNI in md_close because eviction calls cxil_unmap.
     */
    if (md->ats_md == NULL && cfg->enable_rcache != UCS_NO) {
        ucs_rcache_set_params(&rcache_params, &cfg->rcache);
        rcache_params.region_struct_size = sizeof(uct_cxi_rcache_region_t);
        rcache_params.ucm_events         = UCM_EVENT_VM_UNMAPPED;
        rcache_params.ucm_event_priority = cfg->rcache.event_prio;
        rcache_params.context            = md;
        rcache_params.ops                = &uct_cxi_rcache_ops;
        rcache_params.flags              = UCS_RCACHE_FLAG_PURGE_ON_FORK;

        status = ucs_rcache_create(&rcache_params, md_name, NULL, &md->rcache);
        if (status == UCS_OK) {
            md->super.ops = &uct_cxi_md_rcache_ops;
            ucs_debug("cxi rcache enabled for %s", md_name);
        } else {
            ucs_assert(md->rcache == NULL);
            if (cfg->enable_rcache == UCS_YES) {
                ucs_error("cxi failed to create rcache for %s: %s",
                          md_name, ucs_status_string(status));
                status = UCS_ERR_IO_ERROR;
                goto err_destroy_lni;
            }
            ucs_debug("cxi rcache unavailable for %s (%s); "
                      "using direct registration",
                      md_name, ucs_status_string(status));
        }
    }

    uct_md_vfs_init(component, &md->super, md_name);

    ucs_debug("cxi md open device %s nid 0x%x svc_id %u vni %u lni_id %u "
              "ats %s rcache %s",
              md->device.name, nid, md->svc_id, (unsigned)md->vni,
              md->cxi_lni->id,
              md->ats_md  != NULL ? "enabled" : "disabled",
              md->rcache  != NULL ? "enabled" : "disabled");

    *md_p = &md->super;
    return UCS_OK;

err_destroy_lni:
    ret = cxil_destroy_lni(md->cxi_lni);
    if (ret != 0) {
        ucs_warn("cxil_destroy_lni failed during md_open cleanup: %s",
                 strerror(-ret));
    }

err_close_dev:
    cxil_close_device(md->cxi_dev);

err_free_md:
    ucs_free(md);
    return status;
}


/* -------------------------------------------------------------------------
 * component registration
 * -------------------------------------------------------------------------
 */

uct_component_t uct_cxi_component = {
    .query_md_resources = uct_cxi_query_md_resources,
    .md_open            = uct_cxi_md_open,
    .cm_open            = (uct_component_cm_open_func_t)ucs_empty_function_return_unsupported,
    .rkey_unpack        = uct_cxi_rkey_unpack,
    .rkey_ptr           = (uct_component_rkey_ptr_func_t)ucs_empty_function_return_unsupported,
    .rkey_release       = uct_cxi_rkey_release,
    .rkey_compare       = uct_base_rkey_compare,
    .name               = "cxi",
    .md_config          = {
        .name           = "CXI memory domain",
        .prefix         = "CXI_",
        .table          = uct_cxi_md_config_table,
        .size           = sizeof(uct_cxi_md_config_t)
    },
    .cm_config          = UCS_CONFIG_EMPTY_GLOBAL_LIST_ENTRY,
    .tl_list            = UCT_COMPONENT_TL_LIST_INITIALIZER(&uct_cxi_component),
    .flags              = 0,
    .md_vfs_init        = (uct_component_md_vfs_init_func_t)ucs_empty_function
};
