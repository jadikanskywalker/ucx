/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT interface implementation.
 *
 * Allocates the per-iface libcxi hardware resources and exposes the {nid, pid}
 * address that a remote EP needs to route restricted-mode DMA operations here.
 *
 * Resource groups (allocated in order, destroyed in reverse):
 *   wait_obj → eq_buf → eq_md → evtq → tx.cp → tx.cmdq → tgt.cmdq →
 *   domain → rma.pte[0] / rma.pte_map[0] (+ LE) → tx.op_pool
 *
 * Additional rma.pte[1..UCT_CXI_MAX_LACS-1] are opened lazily by
 * uct_cxi_rma_ensure_lac() in cxi_rma.c on first use of each LAC.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_am.h"
#include "cxi_amo.h"
#include "cxi_ep.h"
#include "cxi_iface.h"
#include "cxi_md.h"
#include "cxi_rma.h"

#include <uct/base/uct_iface.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/sys/stubs.h>
#include <ucs/sys/string.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

// TEMPORARY
#include <stdio.h>


static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_iface_md(uct_cxi_iface_t *iface)
{
    return ucs_derived_of(iface->super.md, uct_cxi_md_t);
}


static ucs_config_field_t uct_cxi_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_cxi_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"MAX_BCOPY", "8192",
     "Maximum payload size in bytes for put_bcopy and get_bcopy operations.\n"
     "Each bcopy descriptor in the pool is (sizeof(header) + MAX_BCOPY) bytes,\n"
     "pre-registered with cxil_map. Default matches the IB RC seg_size convention.",
     ucs_offsetof(uct_cxi_iface_config_t, max_bcopy),
     UCS_CONFIG_TYPE_MEMUNITS},

    UCT_IFACE_MPOOL_CONFIG_FIELDS("BCOPY_", 512, 256, 16mb, 2.0,
                                  "bcopy descriptor",
                                  ucs_offsetof(uct_cxi_iface_config_t, bcopy_mp),
                                  "\nDefault bufs_grow matches TX command queue depth "
                                  "so one chunk can saturate the cmdq without regrowth.\n"
                                  "MAX_BUFS default (512) is bounded so pool exhaustion\n"
                                  "reliably triggers UCS_ERR_NO_RESOURCE / pending-retry\n"
                                  "before outstanding ops can exceed a hardware EQ_SIZE.\n"
                                  "-1 means \"size this pool to EQ_SIZE\".  Workloads \n"
                                  "with many concurrently-busy endpoints on one interface\n"
                                  "should raise this together with TX_OP_MAX_BUFS and\n"
                                  "EQ_SIZE — per-endpoint size for expected in-flight\n"
                                  "operation count."),

    UCT_IFACE_MPOOL_CONFIG_FIELDS("TX_OP_", 512, 256, 16mb, 2.0,
                                  "send-op tracking",
                                  ucs_offsetof(uct_cxi_iface_config_t, op_mp),
                                  "\nUsed by put/get/AM short and zcopy, and AMO post/fetch,\n"
                                  "for completion tracking (no DMA-registered memory).\n"
                                  "MAX_BUFS default (512) is bounded for the same reason as\n"
                                  "BCOPY_MAX_BUFS above; -1 means \"size to EQ_SIZE\".\n"
                                  "Raise together with BCOPY_MAX_BUFS and EQ_SIZE\n"
                                  "for workloads with many concurrently-busy endpoints."),

    {"EQ_SIZE", "1024",
     "Event queue depth (number of hardware completion events).  Acts as a\n"
     "floor: automatically grown to (TX_OP_MAX_BUFS + BCOPY_MAX_BUFS) if their\n"
     "sum exceeds this value, since each in-flight send holds exactly one pool\n"
     "slot until its single EQ completion event is drained. Flooding the EQ\n"
     "will result in expensive flow control. Restricted op pool sizes, and\\\n"
     "or growing the EQ size helps ensure transmit-side resouces exhaust\n"
     "before an endpoint's EQ is saturated.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_size),
     UCS_CONFIG_TYPE_UINT},

    {"AM_RX_NUM_BUFS", "4",
     "Number of AM receive buffers rotated on the PRIORITY list.\n"
     "More buffers reduce the chance of overflow under burst traffic.",
     ucs_offsetof(uct_cxi_iface_config_t, am_rx_num_bufs),
     UCS_CONFIG_TYPE_UINT},

    {"AM_RX_BUF_SIZE", "512k",
     "Size of each AM receive buffer in bytes.\n"
     "Automatically increased to AM_MAX_ZCOPY if that is larger.",
     ucs_offsetof(uct_cxi_iface_config_t, am_rx_buf_size),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"AM_MAX_ZCOPY", "512k",
     "Maximum AM zcopy payload in bytes.  Capped by AM_RX_BUF_SIZE;\n"
     "if AM_MAX_ZCOPY exceeds AM_RX_BUF_SIZE, the buffer size is raised.",
     ucs_offsetof(uct_cxi_iface_config_t, am_max_zcopy),
     UCS_CONFIG_TYPE_MEMUNITS},

    {NULL}
};

static UCS_CLASS_DEFINE_DELETE_FUNC(uct_cxi_iface_t, uct_iface_t);

/*
 * uct_cxi_iface_open_rma_pte — allocate, map, enable, and post a catch-all
 * LE for one RMA portal (pid_offset = lac).  Called once per LAC at iface_open.
 * On error, undoes whatever was partially completed.
 */
static ucs_status_t
uct_cxi_iface_open_rma_pte(uct_cxi_iface_t *self, struct cxil_lni *lni,
                            uint8_t lac)
{
    const union c_event      *ev;
    int                       ret;

    {
        struct cxi_pt_alloc_opts pt_opts = {};
        ret = cxil_alloc_pte(lni, self->evtq, &pt_opts, &self->rma.pte[lac]);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte lac %u: %s", lac, strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    ret = cxil_map_pte(self->rma.pte[lac], self->domain, (int)lac,
                       false, &self->rma.pte_map[lac]);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte lac %u: %s", lac, strerror(-ret));
        goto err_destroy_pte;
    }

    /* Transition PTE DISABLED → ENABLED; spin for STATE_CHANGE event. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = self->rma.pte[lac]->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi SETSTATE lac %u: %d", lac, ret);
            goto err_unmap_pte;
        }
        cxi_cq_ring(self->tgt.cmdq);

        while (!enabled) {
            while ((ev = cxi_eq_get_event(self->evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(self->evtq);
        }
    }

    /* Post catch-all LE so the NIC can resolve IOVAs via this LAC. */
    {
        struct c_target_cmd le = {};
        le.command.opcode        = C_CMD_TGT_APPEND;
        le.ptl_list              = C_PTL_LIST_PRIORITY;
        le.ptlte_index           = self->rma.pte[lac]->ptn;
        le.op_put                = 1;
        le.op_get                = 1;
        le.event_link_disable    = 1;
        le.event_comm_disable    = 1;
        le.event_success_disable = 1;
        le.lac                   = lac;
        le.start                 = 0;
        le.length                = (1ULL << 56) - 1;
        le.ignore_bits           = UINT64_MAX;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &le);
        if (ret != 0) {
            ucs_error("cxi APPEND LE lac %u: %d", lac, ret);
            goto err_unmap_pte;
        }
        cxi_cq_ring(self->tgt.cmdq);
    }

    ucs_debug("cxi RMA PTE lac %u ptn %u enabled",
              (unsigned)lac, self->rma.pte[lac]->ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(self->rma.pte_map[lac]);
    self->rma.pte_map[lac] = NULL;
err_destroy_pte:
    cxil_destroy_pte(self->rma.pte[lac]);
    self->rma.pte[lac] = NULL;
    return UCS_ERR_IO_ERROR;
}

/*
 * uct_cxi_iface_post_am_le — append one PRIORITY ME for AM receive buffer buf_idx.
 *
 * buffer_id=buf_idx is echoed in every C_EVENT_PUT, letting iface_progress
 * identify which rx_buf the data landed in.  min_free triggers NIC auto-unlink
 * when remaining space drops below UCT_CXI_AM_MIN_FREE bytes.
 */
static ucs_status_t
uct_cxi_iface_post_am_le(uct_cxi_iface_t *self, int buf_idx, int restart_seq)
{
    struct c_target_cmd le = {};
    int                 ret;

    le.command.opcode        = C_CMD_TGT_APPEND;
    le.ptl_list              = C_PTL_LIST_PRIORITY;
    le.ptlte_index           = self->am.pte->ptn;
    le.op_put                = 1;
    le.op_get                = 0;
    le.use_once              = 0;
    le.manage_local          = 1;  /* NIC maintains write pointer; start advances per msg */
    le.unrestricted_body_ro  = 1;  /* required companion to manage_local on OVERFLOW LEs */
    le.unrestricted_end_ro   = 1;  /* required companion to manage_local on OVERFLOW LEs */
    le.event_link_disable       = 1;
    le.no_truncate              = 1;  /* reject oversized messages instead of silently truncating */
    le.unexpected_hdr_disable   = 1;  /* don't create per-msg OE in LPE pool; we read directly
                                       * from C_EVENT_PUT and never issue TGT_SEARCH */
    le.restart_seq           = restart_seq; /* 1 on reposts: advance per-PTE seq window */
    le.match_id              = CXI_MATCH_ID_ANY;
    le.buffer_id             = (uint16_t)buf_idx;
    le.lac                   = self->am.rx_mh.cxi_md->lac;
    le.start                 = self->am.rx_mh.iova_offset +
                               (uint64_t)(uintptr_t)(self->am.rx_base +
                                                      buf_idx * self->am.buf_size) +
                               sizeof(uint64_t);
    le.length                = self->am.buf_size - sizeof(uint64_t);
    le.min_free              = UCT_CXI_AM_MIN_FREE;
    le.ignore_bits           = UINT64_MAX;
    le.match_bits            = 0;

    ret = cxi_cq_emit_target(self->tgt.cmdq, &le);
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi AM LE APPEND buf %d: %d", buf_idx, ret);
        return UCS_ERR_IO_ERROR;
    }
    cxi_cq_ring(self->tgt.cmdq);
    ucs_debug("cxi AM LE APPEND buf=%d ptn=%u start=0x%lx len=%zu restart_seq=%d",
             buf_idx, self->am.pte->ptn,
             (unsigned long)le.start, self->am.buf_size, restart_seq);
    return UCS_OK;
}

/*
 * uct_cxi_iface_open_am_pte — open the unrestricted AM portal and post all N
 * receive buffers into the PRIORITY list.
 *
 * The PTE uses is_matching=1 (unrestricted mode) and use_long_event=1 to force
 * 64-byte C_EVENT_TARGET_LONG events with valid rlength, mlength, and start.
 */
static ucs_status_t
uct_cxi_iface_open_am_pte(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    const union c_event *ev;
    ucs_status_t         status;
    int                  ret;

    {
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,   /* unrestricted (messaging) mode */
            .use_long_event = 1    /* force 64-byte events with rlength/start */
        };
        ret = cxil_alloc_pte(lni, self->evtq, &pt_opts, &self->am.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte AM: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    ret = cxil_map_pte(self->am.pte, self->domain, (int)UCT_CXI_PTE_AM,
                       false, &self->am.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte AM: %s", strerror(-ret));
        goto err_destroy_pte;
    }

    /* Transition PTE DISABLED → ENABLED; spin for STATE_CHANGE event. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = self->am.pte->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi AM SETSTATE: %d", ret);
            goto err_unmap_pte;
        }
        cxi_cq_ring(self->tgt.cmdq);

        while (!enabled) {
            while ((ev = cxi_eq_get_event(self->evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(self->evtq);
        }
    }

    self->am.rx_total = 0;

    /* Post all N buffers into the PRIORITY list. */
    {
        unsigned i;
        for (i = 0; i < self->am.num_bufs; i++) {
            status = uct_cxi_iface_post_am_le(self, (int)i, 0);
            if (status != UCS_OK) {
                goto err_unmap_pte;
            }
        }
    }

    ucs_debug("cxi AM PTE ptn %u enabled: %u bufs x %zu bytes at %p",
              self->am.pte->ptn, self->am.num_bufs,
              self->am.buf_size, self->am.rx_base);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(self->am.pte_map);
    self->am.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(self->am.pte);
    self->am.pte = NULL;
    return UCS_ERR_IO_ERROR;
}

/*
 * uct_cxi_send_desc_init — mpool obj_init callback for the bcopy desc pool.
 *
 * Called once per descriptor when its chunk is first allocated.  Precomputes
 * the IOVA of the data area (desc+1) from the chunk's cxil_map registration
 * so that ep_put_bcopy / ep_get_bcopy need zero per-op IOVA arithmetic.
 *
 * iova_offset = cxi_md->iova - chunk_VA  →  IOVA(data) = iova_offset + data_VA
 */
static void uct_cxi_send_desc_init(uct_iface_h tl_iface, void *obj,
                                    uct_mem_h memh)
{
    uct_cxi_send_desc_t  *desc   = obj;
    uct_cxi_mem_handle_t *cxi_mh = (uct_cxi_mem_handle_t *)memh;

    desc->iova = cxi_mh->iova_offset + (uint64_t)(uintptr_t)(desc + 1);
    desc->lac  = cxi_mh->cxi_md->lac;
}

/* op_pool: plain malloc/free, no per-object init needed. */
static ucs_mpool_ops_t uct_cxi_send_op_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL,
    .obj_str       = NULL
};

/* Forward declarations. */
ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p);
static unsigned uct_cxi_iface_progress(uct_iface_h tl_iface);

static uct_iface_ops_t uct_cxi_iface_ops = {
    .ep_put_short             = uct_cxi_ep_put_short,
    .ep_put_bcopy             = uct_cxi_ep_put_bcopy,
    .ep_put_zcopy             = uct_cxi_ep_put_zcopy,
    .ep_get_short             = uct_cxi_ep_get_short,
    .ep_get_bcopy             = uct_cxi_ep_get_bcopy,
    .ep_get_zcopy             = uct_cxi_ep_get_zcopy,
    .ep_am_short              = uct_cxi_ep_am_short,
    .ep_am_short_iov          = (uct_ep_am_short_iov_func_t)ucs_empty_function_return_unsupported,
    .ep_am_bcopy              = uct_cxi_ep_am_bcopy,
    .ep_am_zcopy              = uct_cxi_ep_am_zcopy,
    .ep_atomic_cswap64        = uct_cxi_ep_atomic_cswap64,
    .ep_atomic_cswap32        = uct_cxi_ep_atomic_cswap32,
    .ep_atomic32_post         = uct_cxi_ep_atomic32_post,
    .ep_atomic64_post         = uct_cxi_ep_atomic64_post,
    .ep_atomic32_fetch        = uct_cxi_ep_atomic32_fetch,
    .ep_atomic64_fetch        = uct_cxi_ep_atomic64_fetch,
    .ep_tag_eager_short       = (uct_ep_tag_eager_short_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_bcopy       = (uct_ep_tag_eager_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_zcopy       = (uct_ep_tag_eager_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_zcopy        = (uct_ep_tag_rndv_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_cancel       = (uct_ep_tag_rndv_cancel_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_rndv_request      = (uct_ep_tag_rndv_request_func_t)ucs_empty_function_return_unsupported,
    .iface_tag_recv_zcopy     = (uct_iface_tag_recv_zcopy_func_t)ucs_empty_function_return_unsupported,
    .iface_tag_recv_cancel    = (uct_iface_tag_recv_cancel_func_t)ucs_empty_function_return_unsupported,
    .ep_pending_add           = uct_cxi_ep_pending_add,
    .ep_pending_purge         = uct_cxi_ep_pending_purge,
    .ep_flush                 = uct_cxi_ep_flush,
    .ep_fence                 = uct_cxi_ep_fence,
    .ep_check                 = (uct_ep_check_func_t)ucs_empty_function_return_unsupported,
    .ep_create                = uct_cxi_ep_create,
    .ep_connect               = (uct_ep_connect_func_t)ucs_empty_function_return_unsupported,
    .ep_disconnect            = (uct_ep_disconnect_func_t)ucs_empty_function_return_unsupported,
    .cm_ep_conn_notify        = (uct_cm_ep_conn_notify_func_t)ucs_empty_function_return_unsupported,
    .ep_destroy               = uct_cxi_ep_destroy,
    .ep_get_address           = (uct_ep_get_address_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep         = (uct_ep_connect_to_ep_func_t)ucs_empty_function_return_unsupported,
    .iface_accept             = (uct_iface_accept_func_t)ucs_empty_function_return_unsupported,
    .iface_reject             = (uct_iface_reject_func_t)ucs_empty_function_return_unsupported,
    .iface_flush              = uct_cxi_iface_flush,
    .iface_fence              = uct_base_iface_fence,
    .iface_progress_enable    = uct_base_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = uct_cxi_iface_progress,
    .iface_event_fd_get       = uct_cxi_iface_event_fd_get,
    .iface_event_arm          = (uct_iface_event_arm_func_t)ucs_empty_function_return_unsupported,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_cxi_iface_t),
    .iface_query              = uct_cxi_iface_query,
    .iface_get_device_address = uct_cxi_iface_get_device_address,
    .iface_get_address        = uct_cxi_iface_get_address,
    .iface_is_reachable       = uct_cxi_iface_is_reachable
};

static uct_iface_internal_ops_t uct_cxi_iface_internal_ops = {
    .iface_query_v2         = uct_iface_base_query_v2,
    .iface_estimate_perf    = uct_base_iface_estimate_perf,
    .iface_vfs_refresh      = (uct_iface_vfs_refresh_func_t)ucs_empty_function,
    .ep_query               = (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
    .ep_invalidate          = (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
    .ep_connect_to_ep_v2    = (uct_ep_connect_to_ep_v2_func_t)ucs_empty_function_return_unsupported,
    .iface_is_reachable_v2  = uct_cxi_iface_is_reachable_v2,
    .ep_is_connected        = (uct_ep_is_connected_func_t)ucs_empty_function_return_zero_int,
    .ep_get_device_ep       = (uct_ep_get_device_ep_func_t)ucs_empty_function_return_unsupported,
    .ep_put_sgl_zcopy       = (uct_ep_put_sgl_zcopy_func_t)ucs_empty_function_return_unsupported
};

ucs_status_t uct_cxi_query_devices(uct_md_h md,
                                    uct_tl_device_resource_t **devices_p,
                                    unsigned *num_devices_p)
{
    uct_cxi_md_t             *cxi_md  = ucs_derived_of(md, uct_cxi_md_t);
    uct_tl_device_resource_t *devices;

    devices = ucs_calloc(1, sizeof(*devices), "cxi devices");
    if (devices == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    ucs_strncpy_safe(devices[0].name, cxi_md->device.name,
                     sizeof(devices[0].name));
    devices[0].type       = UCT_DEVICE_TYPE_NET;
    devices[0].sys_device = UCS_SYS_DEVICE_ID_UNKNOWN;

    ucs_debug("cxi query devices md %p name %s nid 0x%x",
              cxi_md, devices[0].name, cxi_md->device.nid);

    *devices_p     = devices;
    *num_devices_p = 1;
    return UCS_OK;
}

UCS_CLASS_INIT_FUNC(uct_cxi_iface_t, uct_md_h md, uct_worker_h worker,
                    const uct_iface_params_t *params,
                    const uct_iface_config_t *tl_config)
{
    const uct_cxi_iface_config_t *config = ucs_derived_of(tl_config,
                                                           uct_cxi_iface_config_t);
    uct_cxi_md_t              *cxi_md   = ucs_derived_of(md, uct_cxi_md_t);
    struct cxil_lni           *lni      = cxi_md->cxi_lni;
    struct cxi_eq_attr         eq_attr;
    struct cxi_cq_alloc_opts   cq_opts;
    ucs_mpool_params_t         mp_params;
    ucs_status_t               status;
    int                        ret;
    unsigned                   op_max_bufs;
    unsigned                   desc_max_bufs;
    size_t                     eq_buf_len;

    UCT_CHECK_PARAM(params->field_mask & UCT_IFACE_PARAM_FIELD_OPEN_MODE,
                    "UCT_IFACE_PARAM_FIELD_OPEN_MODE is not defined");
    if (!(params->open_mode & UCT_IFACE_OPEN_MODE_DEVICE)) {
        ucs_error("cxi: only UCT_IFACE_OPEN_MODE_DEVICE is supported");
        return UCS_ERR_UNSUPPORTED;
    }

    UCS_CLASS_CALL_SUPER_INIT(
            uct_base_iface_t, &uct_cxi_iface_ops, &uct_cxi_iface_internal_ops,
            md, worker, params,
            tl_config UCS_STATS_ARG(
                    (params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) ?
                            params->stats_root :
                            NULL) UCS_STATS_ARG(UCT_CXI_NAME));

    /*
     * Step 1.5: resolve TX pool caps and EQ depth together.
     *
     * Each in-flight op (post/short/zcopy/AMO from op_pool, bcopy/AMO-fetch
     * from desc_pool) holds exactly one pool slot until its single EQ
     * completion event is drained.  If op_max_bufs + desc_max_bufs could
     * exceed the hardware EQ depth, outstanding operations could overrun
     * the EQ before pool exhaustion ever returns UCS_ERR_NO_RESOURCE,
     * causing a silent hardware EQ drop instead of a clean pending-retry
     * (see uct_cxi_ep_pending_add).  So eq_num_events is grown to be at
     * least the sum of any *explicitly finite* pool caps.
     *
     * -1 (UINT_MAX) on either MAX_BUFS config resolves to "size this pool
     * to the full EQ" rather than literal unbounded growth — this keeps
     * the invariant even when a user opts out of an explicit cap on one
     * pool, at the cost of not strictly bounding the total when *both*
     * pools are left at -1 simultaneously (an explicit, documented
     * simplification: each -1 pool independently gets the full EQ depth).
     */
    {
        unsigned op_cfg   = config->op_mp.max_bufs;
        unsigned desc_cfg = config->bcopy_mp.max_bufs;
        unsigned finite_sum = (op_cfg == UINT_MAX ? 0 : op_cfg) +
                              (desc_cfg == UINT_MAX ? 0 : desc_cfg);

        self->eq_num_events = ucs_max(config->eq_size, finite_sum);
        op_max_bufs          = (op_cfg == UINT_MAX) ? self->eq_num_events : op_cfg;
        desc_max_bufs        = (desc_cfg == UINT_MAX) ? self->eq_num_events : desc_cfg;
    }
    eq_buf_len = (size_t)self->eq_num_events * UCT_CXI_EQ_ENTRY_SIZE;

    /* Step 2: wait object (epoll fd for event-driven progress). */
    ret = cxil_alloc_wait_obj(lni, &self->wait_obj);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_wait_obj failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* Step 3: mmap a private anonymous buffer for the event queue ring. */
    self->eq_buf = mmap(NULL, eq_buf_len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (self->eq_buf == MAP_FAILED) {
        ucs_error("cxi mmap eq_buf size %zu failed: %m", eq_buf_len);
        status = UCS_ERR_NO_MEMORY;
        goto err_destroy_wait_obj;
    }

    /* Step 4: pin the EQ buffer so the NIC can DMA into it. */
    ret = cxil_map(lni, self->eq_buf, eq_buf_len,
                   CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE,
                   NULL, &self->eq_md);
    if (ret != 0) {
        ucs_error("cxi cxil_map eq_buf failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_munmap_eq;
    }

    /* Step 5: allocate the event queue backed by the pinned buffer. */
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.queue     = self->eq_buf;
    eq_attr.queue_len = eq_buf_len;
    ret = cxil_alloc_evtq(lni, self->eq_md, &eq_attr,
                          self->wait_obj, NULL, &self->evtq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_evtq failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_eq;
    }

    /* Step 6: TX communication profile. */
    ret = cxil_alloc_cp(lni, cxi_md->vni,
                        CXI_TC_BEST_EFFORT, CXI_TC_TYPE_DEFAULT, &self->tx.cp);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cp vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_evtq;
    }

    /* Step 7: TX command queue. */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    cq_opts.flags = CXI_CQ_IS_TX;
    cq_opts.lcid  = self->tx.cp->lcid;
    ret = cxil_alloc_cmdq(lni, self->evtq, &cq_opts, &self->tx.cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tx failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_cp;
    }

    /* Step 8: target command queue (LE management). */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    ret = cxil_alloc_cmdq(lni, self->evtq, &cq_opts, &self->tgt.cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tg failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tx_cmdq;
    }

    /* Step 9: domain (VNI + PID). */
    ret = cxil_alloc_domain(lni, cxi_md->vni, C_PID_ANY, &self->domain);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_domain vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tg_cmdq;
    }

    /*
     * Steps 10–11: open UCT_CXI_MAX_LACS RMA PTEs (one per LAC, eagerly).
     *
     * Building all DFAs at ep_create requires all PTEs open at iface_open so
     * the hot path never needs to check "is PTE N ready?" — it just uses
     * ep->dfa_rma[rkey->lac] directly with no conditional.
     */
    {
        uint8_t lac;
        for (lac = 0; lac < UCT_CXI_MAX_LACS; lac++) {
            status = uct_cxi_iface_open_rma_pte(self, lni, lac);
            if (status != UCS_OK) {
                goto err_rma_ptes;
            }
            self->rma.lac_count++;
        }
    }

    /*
     * Step 12: send-op pool for zcopy/short completion tracking.
     *
     * max_elems = op_max_bufs (resolved in Step 1.5 from TX_OP_MAX_BUFS,
     * with -1 meaning "size to eq_num_events") so pool exhaustion returns
     * UCS_ERR_NO_RESOURCE — triggering the pending-retry path — before
     * outstanding ops can exceed the hardware EQ depth.
     */
    self->tx.outstanding = 0;
    ucs_arbiter_init(&self->tx.arbiter);
    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_send_op_t);
    /* ucs_mpool_init() requires max_elems >= elems_per_chunk; clamp so a
     * small TX_OP_MAX_BUFS (e.g. in tests) doesn't violate that. */
    mp_params.elems_per_chunk = ucs_min(UCT_CXI_CMDQ_DEPTH, op_max_bufs);
    mp_params.max_elems       = op_max_bufs;
    mp_params.ops             = &uct_cxi_send_op_mpool_ops;
    mp_params.name            = "cxi-send-op";
    status = ucs_mpool_init(&mp_params, &self->tx.op_pool);
    if (status != UCS_OK) {
        ucs_error("cxi send_op mpool init failed: %s",
                  ucs_status_string(status));
        goto err_rma_ptes;
    }

    /*
     * Step 12.5: bcopy desc pool — DMA-registered bounce buffers.
     *
     * uct_iface_mpool_init allocates each chunk via the iface's alloc_methods
     * (heap/mmap) then calls uct_md_mem_reg → cxil_map; the resulting
     * uct_cxi_mem_handle_t is passed to uct_cxi_send_desc_init per element.
     * One chunk = UCT_CXI_CMDQ_DEPTH descs ≈ 2 MB, matching the TX cmdq depth
     * so the queue can fill without triggering a second cxil_map.
     *
     * max_bufs is overridden to desc_max_bufs (resolved in Step 1.5) rather
     * than passed straight from config->bcopy_mp — see Step 1.5 for the -1
     * ("size to EQ") resolution.
     */
    self->tx.max_bcopy = config->max_bcopy;
    {
        uct_iface_mpool_config_t desc_mp_config = config->bcopy_mp;
        /* ucs_mpool_init() requires max_elems >= elems_per_chunk; clamp both
         * the explicit BCOPY_BUFS_GROW override and the "grow" fallback
         * below so a small BCOPY_MAX_BUFS (e.g. in tests) doesn't violate
         * that. bufs_grow == 0 keeps its "let the transport pick" meaning. */
        unsigned desc_grow = ucs_min(UCT_CXI_CMDQ_DEPTH, desc_max_bufs);

        desc_mp_config.max_bufs = desc_max_bufs;
        if ((desc_mp_config.bufs_grow != 0) &&
            (desc_mp_config.bufs_grow > desc_max_bufs)) {
            desc_mp_config.bufs_grow = desc_grow;
        }

        status = uct_iface_mpool_init(
                &self->super, &self->tx.desc_pool,
                sizeof(uct_cxi_send_desc_t) + config->max_bcopy,
                sizeof(uct_cxi_send_desc_t),  /* align_offset: align data area */
                UCS_SYS_CACHE_LINE_SIZE,
                &desc_mp_config,
                desc_grow,
                uct_cxi_send_desc_init,
                "cxi-send-desc");
    }
    if (status != UCS_OK) {
        ucs_error("cxi send_desc mpool init failed: %s",
                  ucs_status_string(status));
        goto err_cleanup_op_pool;
    }

    /*
     * Step 13: allocate and register the short-GET scratch buffer.
     *
     * Allocated separately from the iface struct so the NIC's DMA writes
     * land in their own pages, keeping CPU-hot struct fields out of the
     * NIC-written cache lines.
     */
    /* Page-align the scratch buffer so cxi_md->iova == IOVA(get_short_buf).
     * cxil_map returns a page-granule IOVA (cxi_md->iova = page start); if the
     * buffer is not at the page start, cmd.local_addr misses the buffer and the
     * NIC DMA-writes into a different offset within the page. */
    ret = ucs_posix_memalign((void **)&self->tx.get_short_buf,
                             ucs_get_page_size(), C_MAX_IDC_PAYLOAD_RES,
                             "cxi-get-short-buf");
    if (ret != 0) {
        status = UCS_ERR_NO_MEMORY;
        goto err_cleanup_desc_pool;
    }

    status = uct_cxi_do_map(lni, self->tx.get_short_buf, C_MAX_IDC_PAYLOAD_RES,
                            &self->tx.get_short_mh);
    if (status != UCS_OK) {
        goto err_free_get_short_buf;
    }

    /*
     * Step 14: AM receive buffers — one contiguous allocation, single cxil_map.
     *
     * Page-aligned so that iova_offset + VA gives the exact IOVA of each
     * buffer slice — required for start/offset arithmetic in iface_progress.
     */
    self->am.num_bufs = ucs_min(config->am_rx_num_bufs,
                                UCT_CXI_AM_RX_NUM_BUFS_MAX);
    self->am.buf_size = ucs_max(config->am_rx_buf_size,
                                config->am_max_zcopy);
    self->am.rx_base  = NULL;
    {
        size_t total = self->am.num_bufs * self->am.buf_size;
        ret = ucs_posix_memalign((void **)&self->am.rx_base,
                                 ucs_get_page_size(), total,
                                 "cxi-am-rx-buf");
        if (ret != 0) {
            status = UCS_ERR_NO_MEMORY;
            goto err_am_rx_bufs;
        }
        status = uct_cxi_do_map(lni, self->am.rx_base, total,
                                &self->am.rx_mh);
        if (status != UCS_OK) {
            ucs_free(self->am.rx_base);
            self->am.rx_base = NULL;
            goto err_am_rx_bufs;
        }
    }

    status = uct_cxi_iface_open_am_pte(self, lni);
    if (status != UCS_OK) {
        goto err_am_rx_bufs;
    }

    ucs_info("cxi iface open %p nid 0x%x pid %u ptn %u pid_bits %u "
             "max_lacs %u",
             self, cxi_md->device.nid, self->domain->pid,
             self->rma.pte[0]->ptn, (unsigned)cxi_md->pid_bits,
             (unsigned)UCT_CXI_MAX_LACS);
    return UCS_OK;

err_am_rx_bufs:
    if (self->am.rx_base != NULL) {
        uct_cxi_do_unmap(&self->am.rx_mh);
        ucs_free(self->am.rx_base);
        self->am.rx_base = NULL;
    }
err_unmap_get_short:
    uct_cxi_do_unmap(&self->tx.get_short_mh);
err_free_get_short_buf:
    ucs_free(self->tx.get_short_buf);
err_cleanup_desc_pool:
    ucs_mpool_cleanup(&self->tx.desc_pool, 1);
err_cleanup_op_pool:
    ucs_mpool_cleanup(&self->tx.op_pool, 1);
err_rma_ptes:
    {
        uint8_t lac;
        for (lac = UCT_CXI_MAX_LACS; lac-- > 0; ) {
            if (self->rma.pte_map[lac] != NULL) {
                cxil_unmap_pte(self->rma.pte_map[lac]);
            }
            if (self->rma.pte[lac] != NULL) {
                cxil_destroy_pte(self->rma.pte[lac]);
            }
        }
    }
err_destroy_domain:
    cxil_destroy_domain(self->domain);
err_destroy_tg_cmdq:
    cxil_destroy_cmdq(self->tgt.cmdq);
err_destroy_tx_cmdq:
    cxil_destroy_cmdq(self->tx.cmdq);
err_destroy_cp:
    cxil_destroy_cp(self->tx.cp);
err_destroy_evtq:
    cxil_destroy_evtq(self->evtq);
err_unmap_eq:
    cxil_unmap(self->eq_md);
err_munmap_eq:
    munmap(self->eq_buf, eq_buf_len);
err_destroy_wait_obj:
    cxil_destroy_wait_obj(self->wait_obj);
err:
    return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_cxi_iface_t)
{
    int     ret;
    uint8_t lac;

    uct_base_iface_progress_disable(&self->super.super,
                                    UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);

    ucs_arbiter_cleanup(&self->tx.arbiter);

    /* Close AM PTE and rx_buf in reverse allocation order. */
    if (self->am.pte_map != NULL) {
        ret = cxil_unmap_pte(self->am.pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte AM failed: %s", strerror(-ret));
        }
    }
    if (self->am.pte != NULL) {
        ret = cxil_destroy_pte(self->am.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte AM failed: %s", strerror(-ret));
        }
    }
    uct_cxi_do_unmap(&self->am.rx_mh);
    ucs_free(self->am.rx_base);

    uct_cxi_do_unmap(&self->tx.get_short_mh);
    ucs_free(self->tx.get_short_buf);

    ucs_mpool_cleanup(&self->tx.desc_pool, 1);
    ucs_mpool_cleanup(&self->tx.op_pool, 1);

    /* Close RMA PTEs in reverse order. */
    for (lac = UCT_CXI_MAX_LACS; lac-- > 0; ) {
        if (self->rma.pte_map[lac] != NULL) {
            ret = cxil_unmap_pte(self->rma.pte_map[lac]);
            if (ret != 0) {
                ucs_warn("cxi cxil_unmap_pte lac %u failed: %s",
                         (unsigned)lac, strerror(-ret));
            }
        }
        if (self->rma.pte[lac] != NULL) {
            ret = cxil_destroy_pte(self->rma.pte[lac]);
            if (ret != 0) {
                ucs_warn("cxi cxil_destroy_pte lac %u failed: %s",
                         (unsigned)lac, strerror(-ret));
            }
        }
    }

    ret = cxil_destroy_domain(self->domain);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_domain failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cmdq(self->tgt.cmdq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cmdq tg failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cmdq(self->tx.cmdq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cmdq tx failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_cp(self->tx.cp);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cp failed: %s", strerror(-ret));
    }

    ret = cxil_destroy_evtq(self->evtq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_evtq failed: %s", strerror(-ret));
    }

    ret = cxil_unmap(self->eq_md);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap eq_md failed: %s", strerror(-ret));
    }

    munmap(self->eq_buf, (size_t)self->eq_num_events * UCT_CXI_EQ_ENTRY_SIZE);

    ret = cxil_destroy_wait_obj(self->wait_obj);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_wait_obj failed: %s", strerror(-ret));
    }

    ucs_debug("cxi iface close %p", self);
}

UCS_CLASS_DEFINE(uct_cxi_iface_t, uct_base_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_cxi_iface_t, uct_iface_t, uct_md_h, uct_worker_h,
                          const uct_iface_params_t*, const uct_iface_config_t*);

ucs_status_t uct_cxi_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);

    uct_base_iface_query(&iface->super, iface_attr);

    iface_attr->cap.flags             = UCT_IFACE_FLAG_CONNECT_TO_IFACE |
                                        UCT_IFACE_FLAG_INTER_NODE |
                                        UCT_IFACE_FLAG_PUT_SHORT |
                                        UCT_IFACE_FLAG_PUT_BCOPY |
                                        UCT_IFACE_FLAG_PUT_ZCOPY |
                                        UCT_IFACE_FLAG_GET_SHORT |
                                        UCT_IFACE_FLAG_GET_BCOPY |
                                        UCT_IFACE_FLAG_GET_ZCOPY |
                                        UCT_IFACE_FLAG_AM_SHORT  |
                                        UCT_IFACE_FLAG_AM_BCOPY  |
                                        UCT_IFACE_FLAG_AM_ZCOPY  |
                                        UCT_IFACE_FLAG_CB_SYNC   |
                                        UCT_IFACE_FLAG_PENDING  |
                                        UCT_IFACE_FLAG_ATOMIC_DEVICE;

    iface_attr->cap.atomic32.op_flags  = UCS_BIT(UCT_ATOMIC_OP_ADD) |
                                         UCS_BIT(UCT_ATOMIC_OP_AND) |
                                         UCS_BIT(UCT_ATOMIC_OP_OR)  |
                                         UCS_BIT(UCT_ATOMIC_OP_XOR);
    iface_attr->cap.atomic32.fop_flags = iface_attr->cap.atomic32.op_flags |
                                         UCS_BIT(UCT_ATOMIC_OP_SWAP) |
                                         UCS_BIT(UCT_ATOMIC_OP_CSWAP);
    iface_attr->cap.atomic64.op_flags  = iface_attr->cap.atomic32.op_flags;
    iface_attr->cap.atomic64.fop_flags = iface_attr->cap.atomic32.fop_flags;

    iface_attr->cap.put.max_short     = C_MAX_IDC_PAYLOAD_RES;  /* 224 B */
    iface_attr->cap.put.max_bcopy     = iface->tx.max_bcopy;
    iface_attr->cap.put.max_zcopy     = UINT_MAX;
    iface_attr->cap.put.min_zcopy     = 0;
    iface_attr->cap.put.max_iov       = 1;
    iface_attr->cap.put.opt_zcopy_align = sizeof(uint64_t);
    iface_attr->cap.put.align_mtu     = 8;

    iface_attr->cap.get.max_short     = C_MAX_IDC_PAYLOAD_RES;  /* 224 B */
    iface_attr->cap.get.max_bcopy     = iface->tx.max_bcopy;
    iface_attr->cap.get.max_zcopy     = UINT_MAX;
    iface_attr->cap.get.min_zcopy     = 0;
    iface_attr->cap.get.max_iov       = 1;
    iface_attr->cap.get.opt_zcopy_align = sizeof(uint64_t);
    iface_attr->cap.get.align_mtu     = 8;

    iface_attr->cap.am.max_short      = C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t);
    iface_attr->cap.am.max_bcopy      = iface->tx.max_bcopy;
    iface_attr->cap.am.max_hdr        = sizeof(uint64_t);
    iface_attr->cap.am.max_zcopy      = iface->am.buf_size - sizeof(uint64_t);
    iface_attr->cap.am.opt_zcopy_align = sizeof(uint64_t);
    iface_attr->cap.am.align_mtu      = 1;
    iface_attr->cap.am.max_iov        = 1;

    iface_attr->device_addr_len       = sizeof(uct_cxi_device_addr_t);
    iface_attr->iface_addr_len        = sizeof(uct_cxi_iface_addr_t);
    iface_attr->ep_addr_len           = 0;
    iface_attr->max_conn_priv         = 0;
    iface_attr->max_num_eps           = UCS_MEMUNITS_INF;
    iface_attr->bandwidth.dedicated   = 25000.0 * UCS_MBYTE; /* 200 Gb/s */
    iface_attr->bandwidth.shared      = 0;
    iface_attr->latency               = ucs_linear_func_make(1500e-9, 0);
    iface_attr->overhead              = 80e-9;
    iface_attr->priority              = 0;

    return UCS_OK;
}

/*
 * uct_cxi_iface_progress — poll the event queue for send completions.
 *
 * Handles initiator-side TX completions and target-side AM receives.
 *
 * C_EVENT_ACK  — restricted PUT (RMA) confirmed by remote NIC.
 * C_EVENT_REPLY — GET data returned.
 * C_EVENT_SEND  — unrestricted PUT (AM bcopy) locally sent; src buf safe to free.
 * C_EVENT_PUT   — AM message landed in OVERFLOW LE on this iface.
 *
 * ACK, REPLY, and SEND all carry the send_op pointer in init_short.user_ptr.
 */
static unsigned uct_cxi_iface_progress(uct_iface_h tl_iface)
{
    uct_cxi_iface_t     *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    const union c_event *event;
    uct_cxi_send_op_t   *op;
    unsigned             n = 0;

    while ((event = cxi_eq_get_event(iface->evtq)) != NULL) {
        if (event->hdr.event_type == C_EVENT_ACK  ||
            event->hdr.event_type == C_EVENT_REPLY) {
            /* Initiator-side TX completion.
             * ACK   = restricted PUT confirmed by remote (RMA).
             * REPLY = GET data returned (RMA). */
            op = (uct_cxi_send_op_t *)(uintptr_t)event->init_short.user_ptr;
            if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
                ucs_error("cxi TX event %d error: rc=%d ep %p",
                          (int)event->hdr.event_type,
                          cxi_event_rc(event), op->ep);
                if (cxi_event_rc(event) == C_RC_ENTRY_NOT_FOUND &&
                    iface->am.pte != NULL) {
                    struct cxi_pte_status pte_s = {};
                    if (cxil_pte_status(iface->am.pte, &pte_s) == 0) {
                        ucs_error("cxi AM PTE state=%u drop_count=%u ule_count=%u",
                                  pte_s.state, pte_s.drop_count, pte_s.ule_count);
                    }
                }
            }
            op->ep->outstanding--;
            iface->tx.outstanding--;
            if (op->ep->outstanding == 0 && op->ep->flush_comp != NULL) {
                uct_invoke_completion(op->ep->flush_comp, UCS_OK);
                op->ep->flush_comp = NULL;
            }
            ucs_trace("cxi TX event %d rc=%d ep %p outstanding=%u",
                      (int)event->hdr.event_type,
                      cxi_event_rc(event), op->ep, op->ep->outstanding);
            if (op->handler != NULL) {
                op->handler(op);       /* bcopy: handler owns comp + mpool_put */
            } else {
                if (op->comp != NULL) {
                    uct_invoke_completion(op->comp, UCS_OK);
                }
                ucs_mpool_put(op);     /* zcopy / short */
            }
        } else if (event->hdr.event_type == C_EVENT_PUT) {
            /* Target-side AM receive.  buffer_id identifies which rx_buf the
             * NIC wrote into.  start is the absolute IOVA of the first byte. */
            int      buf_idx  = (int)event->tgt_long.buffer_id;
            uint8_t *buf_va   = iface->am.rx_base +
                                buf_idx * iface->am.buf_size;
            uint64_t buf_iova = iface->am.rx_mh.iova_offset +
                                (uint64_t)(uintptr_t)buf_va;
            uint32_t len      = event->tgt_long.mlength;
            uint8_t  am_id    = (uint8_t)(event->tgt_long.match_bits & 0x1f);
            void    *data     = buf_va +
                                (size_t)(event->tgt_long.start - buf_iova);

            // ucs_trace("cxi C_EVENT_PUT: buf=%d ptl_list=%d "
            //           "am_id=%u mlength=%u rlength=%u "
            //           "start=0x%lx remote_offset=0x%lx buf_iova=0x%lx "
            //           "offset=%zu auto_unlinked=%u rc=%d",
            //           buf_idx, (int)event->tgt_long.ptl_list,
            //           (unsigned)am_id, (unsigned)len,
            //           (unsigned)event->tgt_long.rlength,
            //           (unsigned long)event->tgt_long.start,
            //           (unsigned long)event->tgt_long.remote_offset,
            //           (unsigned long)buf_iova,
            //           (size_t)(event->tgt_long.start - buf_iova),
            //           (unsigned)event->tgt_long.auto_unlinked,
            //           cxi_event_rc(event));

            if (ucs_unlikely(event->tgt_long.match_bits &
                             UCT_CXI_AM_HDR_FLAG)) {
                uint64_t hdr = event->tgt_long.header_data;
                memcpy((uint8_t *)data - sizeof(uint64_t),
                       &hdr, sizeof(uint64_t));
                data = (uint8_t *)data - sizeof(uint64_t);
                len += sizeof(uint64_t);
            }

            // if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
            //     ucs_info("cxi AM LE auto_unlinked buf=%d",
            //              buf_idx);
            // }

            uct_iface_invoke_am(&iface->super, am_id, data, len, 0);

            // /* Periodic pte_status diagnostic: log les_allocated + ule_count
            //  * every 50 total received messages to catch LE disappearance. */
            // if ((++iface->am.rx_total % 50) == 0 && iface->am.pte != NULL) {
            //     struct cxi_pte_status pte_s = {};
            //     if (cxil_pte_status(iface->am.pte, &pte_s) == 0) {
            //         ucs_info("cxi AM PTE periodic rx_total=%u: "
            //                  "state=%u drop_count=%u les_alloc=%u ule_count=%u",
            //                  iface->am.rx_total, pte_s.state,
            //                  pte_s.drop_count, pte_s.les_allocated,
            //                  pte_s.ule_count);
            //     }
            // }
        } else if (event->hdr.event_type == C_EVENT_UNLINK) {
            /* LE was auto-unlinked (min_free) or software-unlinked.  Repost
             * at the tail of the PRIORITY list so the ring keeps rotating. */
            int u_buf = (int)event->tgt_long.buffer_id;
            // ucs_info("cxi AM LE C_EVENT_UNLINK buf=%d → reposting",
            //          u_buf);
            uct_cxi_iface_post_am_le(iface, u_buf, 1);
        } else if (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) {
            ucs_info("cxi C_EVENT_PUT_OVERFLOW: ptl_list=%d am_id=%u "
                     "mlength=%u start=0x%lx remote_offset=0x%lx rc=%d",
                     (int)event->tgt_long.ptl_list,
                     (unsigned)(event->tgt_long.match_bits & 0x1f),
                     (unsigned)event->tgt_long.mlength,
                     (unsigned long)event->tgt_long.start,
                     (unsigned long)event->tgt_long.remote_offset,
                     cxi_event_rc(event));
        } else {
            ucs_info("cxi iface_progress: unhandled event type %d rc=%d",
                     (int)event->hdr.event_type, cxi_event_rc(event));
        }
        n++;
    }

    // TEMPORARY
    fflush(stdout);

    if (ucs_unlikely(cxi_eq_get_drops(iface->evtq))) {
        ucs_error("cxi EQ drop detected: events lost (EQ full)");
        cxi_eq_ack_drops(iface->evtq);
    }

    if (n > 0) {
        cxi_eq_ack_events(iface->evtq);
    }

    /* Retry any sends queued via uct_ep_pending_add() now that this round
     * of completions may have freed cmdq/op_pool/desc_pool resources.
     * Cheap no-op when the arbiter is empty. */
    ucs_arbiter_dispatch(&iface->tx.arbiter, 1, uct_cxi_ep_process_pending,
                         NULL);

    return n;
}

ucs_status_t uct_cxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                  uct_completion_t *comp)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);

    if (iface->tx.outstanding == 0) {
        UCT_TL_IFACE_STAT_FLUSH(ucs_derived_of(tl_iface, uct_base_iface_t));
        return UCS_OK;
    }

    UCT_TL_IFACE_STAT_FLUSH_WAIT(ucs_derived_of(tl_iface, uct_base_iface_t));
    return UCS_INPROGRESS;
}

ucs_status_t uct_cxi_iface_get_device_address(uct_iface_h tl_iface,
                                               uct_device_addr_t *dev_addr)
{
    uct_cxi_iface_t       *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_device_addr_t *a     = (uct_cxi_device_addr_t *)dev_addr;

    a->nid = uct_cxi_iface_md(iface)->device.nid;
    return UCS_OK;
}

ucs_status_t uct_cxi_iface_get_address(uct_iface_h tl_iface,
                                        uct_iface_addr_t *iface_addr)
{
    uct_cxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_iface_addr_t *a     = (uct_cxi_iface_addr_t *)iface_addr;

    /* Advertise only the PID; pid_offsets are protocol constants. */
    a->pid = iface->domain->pid;
    return UCS_OK;
}

int uct_cxi_iface_is_reachable(uct_iface_h tl_iface,
                                const uct_device_addr_t *dev_addr,
                                const uct_iface_addr_t *iface_addr)
{
    return 1; /* All Slingshot NIDs are fabric-reachable. */
}

int uct_cxi_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                   const uct_iface_is_reachable_params_t *params)
{
    return uct_iface_is_reachable_params_valid(
                   params, UCT_IFACE_IS_REACHABLE_FIELD_DEVICE_ADDR) &&
           uct_iface_scope_is_reachable(tl_iface, params);
}

ucs_status_t uct_cxi_iface_event_fd_get(uct_iface_h tl_iface, int *fd_p)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    *fd_p = cxil_get_wait_obj_fd(iface->wait_obj);
    return UCS_OK;
}

UCT_TL_DEFINE_ENTRY(&uct_cxi_component, cxi, uct_cxi_query_devices,
                    uct_cxi_iface_t, "CXI_", uct_cxi_iface_config_table,
                    uct_cxi_iface_config_t);

UCT_SINGLE_TL_INIT(&uct_cxi_component, cxi, ctor,,)
