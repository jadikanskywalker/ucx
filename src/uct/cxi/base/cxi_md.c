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
 *   mkey_pack           — serialize {nid, iova, lac} for remote peer
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>


static ucs_config_field_t uct_cxi_md_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_cxi_md_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},
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
 * Guard: if SLINGSHOT_SVC_IDS is not set the Slingshot SLURM plugin has not
 * fired (single-node job or non-Slingshot system).  Advertise no resources
 * in that case so UCX falls back gracefully.
 *
 * When credentials are present we call cxil_get_device_list() and return one
 * MD resource per physical CXI device.  This mirrors the UGNI guard on
 * PMI_GNI_PTAG.
 */
ucs_status_t uct_cxi_query_md_resources(uct_component_h component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p)
{
    struct cxil_device_list *dev_list = NULL;
    uct_md_resource_desc_t  *resources;
    unsigned int             i;
    int                      ret;

    /* Guard: only present resources when the SLURM plugin has fired. */
    if (getenv("SLINGSHOT_SVC_IDS") == NULL) {
        ucs_debug("cxi SLINGSHOT_SVC_IDS not set, no devices advertised");
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

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

    resources = ucs_calloc(dev_list->count, sizeof(*resources),
                           "cxi md resources");
    if (resources == NULL) {
        cxil_free_device_list(dev_list);
        return UCS_ERR_NO_MEMORY;
    }

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
    *num_resources_p = dev_list->count;
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
 * uct_cxi_md_mem_reg - pin host memory and obtain a libcxi memory descriptor.
 *
 * cxil_map() pins the pages, programs the NIC's ATU, and returns a
 * struct cxi_md containing:
 *   .iova  — NIC-visible base address (used in DMA descriptors)
 *   .lac   — memory access class tag (must accompany every DMA reference)
 *   .len   — length of the mapping
 *
 * CXI_MAP_PIN ensures physical page pinning (required for DMA).
 * CXI_MAP_READ | CXI_MAP_WRITE grants bidirectional NIC access.
 */
static ucs_status_t uct_cxi_md_mem_reg(uct_md_h mdh, void *address,
                                       size_t length,
                                       const uct_md_mem_reg_params_t *params,
                                       uct_mem_h *memh_p)
{
    uct_cxi_md_t          *md = ucs_derived_of(mdh, uct_cxi_md_t);
    uct_cxi_mem_handle_t  *mh;
    int                    flags = CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE;
    int                    ret;

    mh = ucs_malloc(sizeof(*mh), "uct_cxi_mem_handle");
    if (mh == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    ret = cxil_map(md->cxi_lni, address, length, flags, NULL, &mh->cxi_md);
    if (ret != 0) {
        ucs_error("cxil_map lni_id %u addr %p len %zu failed: %s",
                  md->cxi_lni->id, address, length, strerror(-ret));
        ucs_free(mh);
        return UCS_ERR_IO_ERROR;
    }

    ucs_debug("cxi mem reg addr %p len %zu iova 0x%"PRIx64" lac %u",
              address, length, (uint64_t)mh->cxi_md->iova,
              (unsigned)mh->cxi_md->lac);

    *memh_p = mh;
    return UCS_OK;
}

static ucs_status_t
uct_cxi_md_mem_dereg(uct_md_h mdh, const uct_md_mem_dereg_params_t *params)
{
    uct_cxi_mem_handle_t *mh = params->memh;
    int                   ret;

    ret = cxil_unmap(mh->cxi_md);
    if (ret != 0) {
        ucs_warn("cxil_unmap failed: %s", strerror(-ret));
    }

    ucs_free(mh);
    return UCS_OK;
}


/* -------------------------------------------------------------------------
 * mkey_pack / rkey_unpack — remote key serialization
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_md_mkey_pack - serialize enough information for a remote peer to
 * DMA into/from this buffer.
 *
 * The packed key contains:
 *   nid   — this NIC's address (peer uses it to route the DMA)
 *   iova  — NIC-visible base address of the registered region
 *   lac   — memory access class (must appear in every NIC DMA command that
 *            references this mapping)
 *
 * The peer stores this in a uct_cxi_rkey_t and uses CXI_VA_TO_IOVA() to
 * compute the exact target IOVA for a sub-region request.
 */
static ucs_status_t
uct_cxi_md_mkey_pack(uct_md_h mdh, uct_mem_h memh, void *address,
                     size_t length, const uct_md_mkey_pack_params_t *params,
                     void *mkey_buffer)
{
    uct_cxi_md_t          *md = ucs_derived_of(mdh, uct_cxi_md_t);
    uct_cxi_mem_handle_t  *mh = memh;
    uct_cxi_rkey_t        *rkey = mkey_buffer;

    rkey->nid  = md->device.nid;
    rkey->iova = mh->cxi_md->iova;
    rkey->lac  = mh->cxi_md->lac;

    ucs_debug("cxi mkey pack nid 0x%x iova 0x%"PRIx64" lac %u",
              rkey->nid, rkey->iova, (unsigned)rkey->lac);
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

    ucs_debug("cxi rkey unpack nid 0x%x iova 0x%"PRIx64" lac %u",
              rkey->nid, rkey->iova, (unsigned)rkey->lac);
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
                                         uct_md_mem_attr_t *attr)
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

ucs_status_t uct_cxi_md_open(uct_component_h component, const char *md_name,
                             const uct_md_config_t *md_config, uct_md_h *md_p)
{
    struct cxi_svc_desc  svc_desc = {};
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

    /* Read credentials injected by the Slingshot SLURM plugin. */
    svc_id = uct_cxi_get_svc_id(dev_id);
    if (svc_id < 0) {
        ucs_error("cxi no service ID for device %s (dev_id %u)", md_name,
                  dev_id);
        return UCS_ERR_NO_DEVICE;
    }

    vni = uct_cxi_get_vni();
    if (vni == 0) {
        ucs_error("cxi no VNI found (SLINGSHOT_VNIS not set or zero)");
        return UCS_ERR_NO_DEVICE;
    }

    ucs_debug("cxi opening device %s dev_id %u svc_id %d vni %u",
              md_name, dev_id, svc_id, (unsigned)vni);

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

    uct_md_vfs_init(component, &md->super, md_name);

    ucs_debug("cxi md open device %s nid 0x%x svc_id %u vni %u lni_id %u",
              md->device.name, nid, md->svc_id, (unsigned)md->vni,
              md->cxi_lni->id);

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

UCT_COMPONENT_REGISTER(&uct_cxi_component);
