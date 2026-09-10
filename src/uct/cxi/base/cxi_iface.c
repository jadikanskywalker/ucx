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
 *   domain → rma.pte[0..UCT_CXI_MAX_LACS-1] (+ one LE each) → tx.op_pool
 *
 * All UCT_CXI_MAX_LACS RMA PTEs are opened eagerly here, not lazily on
 * first use of a LAC -- ep_create builds every ep->dfa_rma[lac] up front
 * (see cxi_ep.c) so the hot path never needs an "is this LAC's PTE open
 * yet?" check.
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
#include "cxi_tag.h"

#include <uct/base/uct_iface.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/sys/math.h>
#include <ucs/sys/ptr_arith.h>
#include <ucs/sys/stubs.h>
#include <ucs/sys/string.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>


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

    {"EQ_SIZE", "-1",
     "Event queue depth (number of hardware completion events). -1 (default)\n"
     "resolves to 1024. TX_OP_MAX_BUFS/BCOPY_MAX_BUFS each independently\n"
     "default (their own -1 sentinel) to half of whatever this resolves to,\n"
     "so the common case of neither being set still sums to exactly this\n"
     "value; an explicitly-set pool cap is used exactly as given, even if\n"
     "that sums past this value — a reachable raw EQ drop from TX-side\n"
     "crowding is then a consequence of that explicit combination, not\n"
     "something silently protected against.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_size),
     UCS_CONFIG_TYPE_INT},

    {"EQ_MAX_POLL", "16",
     "Max events drained from the EQ per iface_progress() call, matching\n"
     "the bounded-poll-per-call pattern every other UCX transport uses\n"
     "(e.g. RC/UD/DC's TX/RX_MAX_POLL, TCP's UCT_TCP_MAX_EVENTS) instead of\n"
     "draining to empty. Without this bound, a steady incoming flood could\n"
     "keep the loop running past the point where the post-loop\n"
     "EQ_DYNAMIC_GROWTH fill-threshold and EQ_DRAIN_PCT drop checks would\n"
     "still have time to act before the EQ actually fills.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_max_poll),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_RESERVED_SLOTS_PCT", "5",
     "Percentage of the EQ reserved so incoming (RX) traffic cannot crowd\n"
     "out this iface's own TX completions. One-sided: TX completions may\n"
     "still use the full EQ, this only blocks LPE/RX events from the\n"
     "reserved portion. A floor, not an exclusive TX partition — safe to\n"
     "default small since PTE flow control (below) is what actually\n"
     "prevents data loss regardless of this setting; raise it for\n"
     "workloads known to be TX-heavy.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_reserved_slots_pct),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_DRAIN_PCT", "50",
     "Percentage of the EQ to drain (counted from the moment a drop is\n"
     "detected) before re-checking and re-enabling any disabled PTE.\n"
     "Re-enabling into a still-full EQ just re-triggers the same disable\n"
     "on the next blocked event, so this avoids flapping under sustained\n"
     "(not transient) pressure.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_drain_pct),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_FLAP_LIMIT", "5",
     "Max disable/re-enable cycles for one PTE within EQ_FLAP_WINDOW\n"
     "before giving up and leaving it disabled (logged as an error)\n"
     "rather than continuing to retry SETSTATE indefinitely.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_flap_limit),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_FLAP_WINDOW", "1s",
     "Time window for EQ_FLAP_LIMIT.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_flap_window),
     UCS_CONFIG_TYPE_TIME},

    {"EQ_DYNAMIC_GROWTH", "y",
     "Preemptively grow (double) the EQ when its fill level crosses\n"
     "EQ_GROW_THRESH_PCT, using Cassini's native resize API, instead of\n"
     "waiting to hit EQ_FULL and recovering reactively (see EQ_DRAIN_PCT).\n"
     "Growth stops at EQ_MAX_LEN; sustained pressure past that point falls\n"
     "back to the reactive path.",
     ucs_offsetof(uct_cxi_iface_config_t, dynamic_eq_growth),
     UCS_CONFIG_TYPE_BOOL},

    {"EQ_GROW_THRESH_PCT", "80",
     "EQ fill percentage that triggers a EQ_DYNAMIC_GROWTH resize.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_grow_thresh_pct),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_MAX_LEN", "65536",
     "Ceiling on EQ_DYNAMIC_GROWTH, in events (same unit as EQ_SIZE).\n"
     "Bounded well below the hardware's own maximum by default so\n"
     "sustained pressure eventually falls back to the reactive\n"
     "drain/backoff path instead of growing pinned memory unboundedly.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_max_len),
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

    {"TAG_ENABLE", "try",
     "Enable hardware tag-matching offload when UCP requests it. \"no\"\n"
     "force-disables it even if requested, falling back to UCX's existing\n"
     "software tag matching over AM.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_enable),
     UCS_CONFIG_TYPE_TERNARY},

    {"TAG_OVERFLOW_NUM_BUFS", "4",
     "Number of overflow-list buffers rotated for unexpected tagged\n"
     "messages (no priority LE posted for them yet).",
     ucs_offsetof(uct_cxi_iface_config_t, tag_ovf_num_bufs),
     UCS_CONFIG_TYPE_UINT},

    {"TAG_OVERFLOW_BUF_SIZE", "512k",
     "Size of each overflow-list buffer in bytes.\n"
     "Automatically increased to TAG_EAGER_MAX if that is larger.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_ovf_buf_size),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"TAG_EAGER_MAX", "512k",
     "Maximum eager tag bcopy/zcopy payload in bytes.  Also sizes the\n"
     "unexpected-message copy-out pool elements.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_eager_max),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"TAG_MAX_OUTSTANDING", "512",
     "Maximum number of simultaneously-posted priority-list receive LEs.\n"
     "Hard ceiling 65535 (the hardware buffer_id correlation field is\n"
     "16 bits).",
     ucs_offsetof(uct_cxi_iface_config_t, tag_max_outstanding),
     UCS_CONFIG_TYPE_UINT},

    {"TAG_UNEXP_MAX_BUFS", "512",
     "Maximum number of buffered unexpected tagged messages awaiting\n"
     "delivery to UCP's software tag matching.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_unexp_max_bufs),
     UCS_CONFIG_TYPE_UINT},

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
        /* en_flowctrl: on EQ-full pressure, transition DISABLED (graceful,
         * accountable via drop_count) instead of silently dropping the
         * event. This LE has event_success_disable=1 below, so it can
         * never itself generate a target-side event needing a slot — the
         * bit is armed here for consistency / in case that ever changes,
         * not because RMA/AMO can hit this path today. */
        struct cxi_pt_alloc_opts pt_opts = {
            .en_flowctrl = 1
        };
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
    le.event_unlink_disable     = 1;  /* UNLINK notification not needed, last PUT carries auto_unlink */
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
        /* en_flowctrl: on EQ-full pressure, transition DISABLED (graceful,
         * accountable via drop_count) instead of silently dropping the
         * event. Unlike RMA/AMO, AM's receive LEs do generate real
         * target-side events (C_EVENT_PUT) — this is the PTE this
         * mechanism actually protects; see iface_progress(). */
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,   /* unrestricted (messaging) mode */
            .use_long_event = 1,   /* force 64-byte events with rlength/start */
            .en_flowctrl    = 1
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
    .ep_tag_eager_short       = uct_cxi_ep_tag_eager_short,
    .ep_tag_eager_bcopy       = uct_cxi_ep_tag_eager_bcopy,
    .ep_tag_eager_zcopy       = uct_cxi_ep_tag_eager_zcopy,
    /* Phase B (direct-match only) -- see the design plan's "Current
     * increment". ep_tag_rndv_request stays unsupported: making it
     * correct needs receive-side rndv_cb dispatch, out of scope here;
     * confirmed safe to defer (ucp_rndv_send_handle_status_from_pending()
     * turns UCS_ERR_UNSUPPORTED into a clean error completion, not a
     * hang). */
    .ep_tag_rndv_zcopy        = uct_cxi_ep_tag_rndv_zcopy,
    .ep_tag_rndv_cancel       = uct_cxi_ep_tag_rndv_cancel,
    .ep_tag_rndv_request      = uct_cxi_ep_tag_rndv_request,
    .iface_tag_recv_zcopy     = uct_cxi_iface_tag_recv_zcopy,
    .iface_tag_recv_cancel    = uct_cxi_iface_tag_recv_cancel,
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
    .ep_put_sgl_zcopy       = (uct_ep_put_sgl_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_get_sgl_zcopy       = (uct_ep_get_sgl_zcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_outstanding_purge   = (uct_ep_outstanding_purge_func_t)ucs_empty_function_return_unsupported
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
     * Step 1.5: resolve EQ depth, then TX pool caps from it.
     *
     * EQ_SIZE uses the same -1/UINT_MAX-sentinel convention as
     * TX_OP_MAX_BUFS/BCOPY_MAX_BUFS below (config table default "-1") —
     * unset resolves to UCT_CXI_EQ_NUM_EVENTS, explicitly set uses that
     * value exactly. This is a real sentinel, not a "differs from the
     * compiled-in default" guess, so a user explicitly setting EQ_SIZE to
     * the same value the default would have produced is still correctly
     * seen as "set" — the config table must keep passing -1 through
     * un-resolved for this check to mean anything; nothing upstream of
     * here may substitute in the default early.
     *
     * Each pool cap keeps its existing, independent meaning for the same
     * sentinel ("unbounded — size this pool from the EQ") — unset
     * resolves to half of eq_num_events each, so that the common case of
     * neither pool being explicitly set still sums to exactly
     * eq_num_events (matching each in-flight op holding one pool slot
     * until its single EQ completion event is drained), rather than each
     * independently claiming the *full* EQ. An explicitly-set pool cap is
     * used exactly as given, even if that (combined with an explicit
     * EQ_SIZE) sums past eq_num_events — a reachable raw EQ drop from
     * TX-side crowding is then a consequence of that explicit, informed
     * choice, not something silently protected against.
     */
    {
        unsigned eq_cfg   = config->eq_size;
        unsigned op_cfg   = config->op_mp.max_bufs;
        unsigned desc_cfg = config->bcopy_mp.max_bufs;

        self->eq_num_events = (eq_cfg == UINT_MAX) ? UCT_CXI_EQ_NUM_EVENTS :
                              eq_cfg;
        op_max_bufs   = (op_cfg == UINT_MAX) ?
                        ucs_max(self->eq_num_events / 2, 1u) : op_cfg;
        desc_max_bufs = (desc_cfg == UINT_MAX) ?
                        ucs_max(self->eq_num_events / 2, 1u) : desc_cfg;
    }
    eq_buf_len = (size_t)self->eq_num_events * UCT_CXI_EQ_ENTRY_SIZE;
    self->eq_max_poll = ucs_max(config->eq_max_poll, 1u);

    /* PTE flow-control recovery config, resolved once here (setup time,
     * not the hot path) — see cxi_iface.h / iface_progress(). */
    self->eq_need_to_drain     = 0;
    self->eq_drain_pct         = config->eq_drain_pct;
    self->eq_flap_limit        = config->eq_flap_limit;
    self->eq_flap_window       = ucs_time_from_sec(config->eq_flap_window);
    self->eq_reserved_slots_pct = config->eq_reserved_slots_pct;
    memset(&self->am.fc, 0, sizeof(self->am.fc));
    memset(self->rma.fc, 0, sizeof(self->rma.fc));

    /* Preemptive EQ growth config — see cxi_iface.h / eq_grow_start(). */
    memset(&self->eq_grow, 0, sizeof(self->eq_grow));
    self->eq_grow.enabled        = config->dynamic_eq_growth;
    self->eq_grow.thresh_pct     = config->eq_grow_thresh_pct;
    self->eq_grow.max_len_events = config->eq_max_len;

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

    /* Step 5: allocate the event queue backed by the pinned buffer.
     * reserved_slots is one-sided (blocks LPE/RX from the reservation,
     * does not cap TX) — see EQ_RESERVED_SLOTS_PCT doc and the design
     * notes in iface_progress(). */
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.queue          = self->eq_buf;
    eq_attr.queue_len      = eq_buf_len;
    eq_attr.reserved_slots = (self->eq_num_events *
                              self->eq_reserved_slots_pct) / 100;
    self->eq_reserved_slots = eq_attr.reserved_slots;
    /* status_thresh_*: a single hardware-native fill-percentage threshold
     * (see EQ_DYNAMIC_GROWTH doc) — status_thresh_count=0 when disabled
     * costs nothing (no status write-backs ever generated). */
    if (self->eq_grow.enabled) {
        eq_attr.status_thresh_base  = self->eq_grow.thresh_pct;
        eq_attr.status_thresh_delta = 0;
        eq_attr.status_thresh_count = 1;
    }
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
                            UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
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
                                UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
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

    /*
     * Step 15: hardware tag-matching offload -- a no-op (tag.pte stays
     * NULL) unless UCP requested it (supplied both HW_TM callbacks) and
     * UCX_CXI_TAG_ENABLE != no. See cxi_tag.c.
     */
    status = uct_cxi_iface_open_tag_pte(self, lni, config, params);
    if (status != UCS_OK) {
        goto err_am_pte;
    }

    /*
     * Step 16: rendezvous source-exposure PTE -- only meaningful (and
     * only opened) if tag offload actually enabled above. See cxi_tag.c
     * and the design plan's Part 1 point 4.
     */
    if (self->tag.enabled) {
        status = uct_cxi_iface_open_rdzv_pte(self, lni);
        if (status != UCS_OK) {
            goto err_tag_pte;
        }
    }

    ucs_info("cxi iface open %p nid 0x%x pid %u ptn %u pid_bits %u "
             "max_lacs %u",
             self, cxi_md->device.nid, self->domain->pid,
             self->rma.pte[0]->ptn, (unsigned)cxi_md->pid_bits,
             (unsigned)UCT_CXI_MAX_LACS);
    return UCS_OK;

err_tag_pte:
    uct_cxi_iface_close_tag_pte(self);
err_am_pte:
    if (self->am.pte_map != NULL) {
        cxil_unmap_pte(self->am.pte_map);
        self->am.pte_map = NULL;
    }
    if (self->am.pte != NULL) {
        cxil_destroy_pte(self->am.pte);
        self->am.pte = NULL;
    }
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

    /* A resize left in flight (iface torn down before C_EVENT_EQ_SWITCH
     * arrived) leaks its pending buffer unless freed explicitly here —
     * it's not reachable via the eq_buf/eq_md cleanup below, which only
     * knows about the currently-active buffer. */
    if (self->eq_grow.resizing) {
        ret = cxil_unmap(self->eq_grow.pending_md);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap pending eq_grow buffer failed: %s",
                     strerror(-ret));
        }
        munmap(self->eq_grow.pending_buf, self->eq_grow.pending_len);
    }

    ucs_arbiter_cleanup(&self->tx.arbiter);

    /* Close RDZV PTE first (opened after TAG, so closed before it), then
     * TAG PTE (opened after AM, so closed before it). Both are no-ops if
     * HW tag offload was never enabled for this iface. */
    uct_cxi_iface_close_rdzv_pte(self);
    uct_cxi_iface_close_tag_pte(self);

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

    if (iface->tag.enabled) {
        iface_attr->cap.flags |= UCT_IFACE_FLAG_TAG_EAGER_SHORT |
                                 UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
                                 UCT_IFACE_FLAG_TAG_EAGER_ZCOPY;

        iface_attr->cap.tag.recv.min_recv       = 0;
        iface_attr->cap.tag.recv.max_zcopy      = iface->tag.buf_size;
        iface_attr->cap.tag.recv.max_iov        = 1; /* no send/recv SG anywhere
                                                          in this transport */
        iface_attr->cap.tag.recv.max_outstanding = iface->tag.max_outstanding;

        iface_attr->cap.tag.eager.max_short = C_MAX_IDC_PAYLOAD_UNR; /* no
                                                 header reservation needed,
                                                 unlike AM -- see cxi_tag.c */
        iface_attr->cap.tag.eager.max_bcopy = iface->tag.buf_size;
        iface_attr->cap.tag.eager.max_zcopy = iface->tag.buf_size;
        iface_attr->cap.tag.eager.max_iov   = 1;

        /* Phase B (direct-match only) -- see the design plan's "Current
         * increment". max_hdr must be >= sizeof(ucp_tag_offload_unexp_
         * rndv_hdr_t) (17 bytes) unconditionally once tag_lane is
         * selected -- UCP asserts this (ucp_ep.c's ucs_assertv_always on
         * rndv.max_hdr) regardless of whether the header is ever
         * meaningfully used. We accept but discard header_length up to
         * this max -- see uct_cxi_ep_tag_rndv_zcopy's own comment on why
         * (header only matters for the genuinely-unexpected case, out of
         * scope this increment). max_zcopy/max_iov bounded by
         * c_full_dma_cmd's own request_len (uint32_t) and our own
         * single-iov restriction. */
        iface_attr->cap.flags              |= UCT_IFACE_FLAG_TAG_RNDV_ZCOPY;
        iface_attr->cap.tag.rndv.max_hdr    = UCT_CXI_TAG_RNDV_MAX_HDR;
        iface_attr->cap.tag.rndv.max_zcopy  = UINT32_MAX;
        iface_attr->cap.tag.rndv.max_iov    = 1;
    }

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
 * uct_cxi_iface_pte_recover — issue SETSTATE(ENABLED) for one PTE if it's
 * currently DISABLED, subject to a per-PTE flap limit.
 *
 * Called only once the shared EQ has been drained by eq_need_to_drain (see
 * iface_progress()) — never immediately on a raw drop, since re-enabling
 * into a still-full EQ just re-triggers the same disable on the PTE's next
 * blocked event.  cxil_pte_status() is queried directly rather than relying
 * on having seen a STATE_CHANGE event for this PTE, since that notification
 * can itself be lost under the same EQ pressure it's meant to report.
 */
static void
uct_cxi_iface_pte_recover(uct_cxi_iface_t *iface, struct cxil_pte *pte,
                          uct_cxi_pte_fc_t *fc)
{
    struct cxi_pte_status  pte_s = {};
    struct c_set_state_cmd ss    = {};
    ucs_time_t             now;
    int                    ret;

    if ((pte == NULL) || fc->gave_up) {
        return;
    }
    if ((cxil_pte_status(pte, &pte_s) != 0) ||
        (pte_s.state != C_PTLTE_DISABLED)) {
        return;
    }

    now = ucs_get_time();
    if ((fc->flap_window_start == 0) ||
        (now - fc->flap_window_start > iface->eq_flap_window)) {
        fc->flap_window_start = now;
        fc->flap_count        = 0;
    }
    if (++fc->flap_count > iface->eq_flap_limit) {
        ucs_error("cxi PTE ptn=%u: exceeded %u disable/re-enable cycles "
                  "within the flap window — giving up, PTE stays disabled",
                  pte->ptn, iface->eq_flap_limit);
        fc->gave_up = 1;
        return;
    }

    ss.command.opcode = C_CMD_TGT_SETSTATE;
    ss.ptlte_index    = pte->ptn;
    ss.ptlte_state    = C_PTLTE_ENABLED;
    ss.drop_count     = pte_s.drop_count;

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &ss);
    if (ucs_unlikely(ret != 0)) {
        ucs_warn("cxi PTE ptn=%u: SETSTATE emit failed: %d", pte->ptn, ret);
        return;
    }
    cxi_cq_ring(iface->tgt.cmdq);
    ucs_debug("cxi PTE ptn=%u: recovering (flap %u/%u), SETSTATE ENABLED "
             "drop_count=%u", pte->ptn, fc->flap_count, iface->eq_flap_limit,
             pte_s.drop_count);
}

/*
 * uct_cxi_iface_recover_ptes — check every locally-owned PTE (AM + each open
 * RMA LAC — bounded by UCT_CXI_MAX_LACS+1, not connection count) and recover
 * any found DISABLED.  Called once the EQ has been drained enough
 * (eq_need_to_drain reaching 0), not per-drop.
 */
static void uct_cxi_iface_recover_ptes(uct_cxi_iface_t *iface)
{
    unsigned lac;

    uct_cxi_iface_pte_recover(iface, iface->am.pte, &iface->am.fc);
    uct_cxi_iface_pte_recover(iface, iface->tag.pte, &iface->tag.fc);
    uct_cxi_iface_pte_recover(iface, iface->rdzv.pte, &iface->rdzv.fc);
    for (lac = 0; lac < iface->rma.lac_count; lac++) {
        uct_cxi_iface_pte_recover(iface, iface->rma.pte[lac],
                                  &iface->rma.fc[lac]);
    }
}

/*
 * uct_cxi_iface_pte_by_index — find the locally-owned PTE (and its
 * recovery/exhaustion state) matching a STATE_CHANGE event's ptlte_index.
 * Checks AM first, then each open RMA LAC. Returns NULL (via *pte_p) if
 * the index doesn't match anything we track — shouldn't happen, but a
 * STATE_CHANGE for a PTE we don't recognize isn't actionable either way.
 */
static uct_cxi_pte_fc_t *
uct_cxi_iface_pte_by_index(uct_cxi_iface_t *iface, uint16_t ptlte_index,
                           struct cxil_pte **pte_p)
{
    unsigned lac;

    if ((iface->am.pte != NULL) && (ptlte_index == iface->am.pte->ptn)) {
        *pte_p = iface->am.pte;
        return &iface->am.fc;
    }
    if ((iface->tag.pte != NULL) && (ptlte_index == iface->tag.pte->ptn)) {
        *pte_p = iface->tag.pte;
        return &iface->tag.fc;
    }
    if ((iface->rdzv.pte != NULL) && (ptlte_index == iface->rdzv.pte->ptn)) {
        *pte_p = iface->rdzv.pte;
        return &iface->rdzv.fc;
    }
    for (lac = 0; lac < iface->rma.lac_count; lac++) {
        if ((iface->rma.pte[lac] != NULL) &&
            (ptlte_index == iface->rma.pte[lac]->ptn)) {
            *pte_p = iface->rma.pte[lac];
            return &iface->rma.fc[lac];
        }
    }
    *pte_p = NULL;
    return NULL;
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


/*
 * uct_cxi_iface_eq_grow_start — begin a preemptive EQ resize.
 *
 * Called from iface_progress() once a hardware fill-threshold status
 * update reports the EQ at or above eq_grow.thresh_pct. Submits a new,
 * double-sized buffer via cxil_evtq_resize() — hardware keeps writing to
 * the old buffer for a few more events, then emits C_EVENT_EQ_SWITCH
 * (handled in the main event loop) once it has switched to the new one.
 *
 * Only one resize may be in flight at a time (enforced by the driver,
 * mirrored here via eq_grow.resizing) — the caller must not call this
 * again until eq_grow_complete() has run.
 */
static void uct_cxi_iface_eq_grow_start(uct_cxi_iface_t *iface)
{
    uct_cxi_md_t  *md = uct_cxi_iface_md(iface);
    size_t         new_len;
    void          *new_buf;
    struct cxi_md *new_md;
    int            ret;

    if (iface->eq_num_events >= iface->eq_grow.max_len_events) {
        ucs_debug("cxi EQ at configured max_len (%u events) — "
                  "not growing further, reactive recovery remains "
                  "the backstop", iface->eq_grow.max_len_events);
        return;
    }

    new_len = ucs_min((size_t)iface->eq_num_events * 2,
                      (size_t)iface->eq_grow.max_len_events) *
             UCT_CXI_EQ_ENTRY_SIZE;
    new_len = ucs_align_up_pow2(new_len, ucs_get_page_size());

    new_buf = mmap(NULL, new_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_buf == MAP_FAILED) {
        ucs_warn("cxi EQ grow: mmap size %zu failed: %m — will retry on "
                 "next threshold crossing", new_len);
        return;
    }

    /* Same flags as the original eq_md (Step 4 in iface_open) — must land
     * on the same LAC as the EQ's current MD, or cxil_evtq_resize() below
     * rejects it. */
    ret = cxil_map(md->cxi_lni, new_buf, new_len,
                   CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE, NULL,
                   &new_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_map failed: %s — will retry on next "
                 "threshold crossing", strerror(-ret));
        munmap(new_buf, new_len);
        return;
    }

    ret = cxil_evtq_resize(iface->evtq, new_buf, new_len, new_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_evtq_resize failed: %s", strerror(-ret));
        cxil_unmap(new_md);
        munmap(new_buf, new_len);
        return;
    }

    iface->eq_grow.pending_buf = new_buf;
    iface->eq_grow.pending_md  = new_md;
    iface->eq_grow.pending_len = new_len;
    iface->eq_grow.resizing    = 1;
    ucs_debug("cxi EQ grow: resize submitted %u -> %zu events",
             iface->eq_num_events, new_len / UCT_CXI_EQ_ENTRY_SIZE);
}

/*
 * uct_cxi_iface_eq_grow_complete — finish a preemptive EQ resize.
 *
 * Called from the main event loop on C_EVENT_EQ_SWITCH. Completes the
 * driver-side handshake, frees the old buffer, and re-applies the
 * reserved-slots percentage against the new (larger) size — otherwise
 * the reserved floor silently shrinks as a fraction of the queue on
 * every doubling.
 */
static void uct_cxi_iface_eq_grow_complete(uct_cxi_iface_t *iface)
{
    void          *old_buf = iface->eq_buf;
    struct cxi_md *old_md  = iface->eq_md;
    size_t         old_len = (size_t)iface->eq_num_events *
                             UCT_CXI_EQ_ENTRY_SIZE;
    unsigned       target_reserved;
    int            ret;

    if (!iface->eq_grow.resizing) {
        ucs_warn("cxi C_EVENT_EQ_SWITCH with no resize in flight — ignoring");
        return;
    }

    ret = cxil_evtq_resize_complete(iface->evtq);
    if (ret != 0) {
        ucs_error("cxi EQ grow: cxil_evtq_resize_complete failed: %s — "
                  "EQ remains at %u events", strerror(-ret),
                  iface->eq_num_events);
        return;
    }

    ret = cxil_unmap(old_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_unmap old buffer failed: %s",
                 strerror(-ret));
    }
    munmap(old_buf, old_len);

    iface->eq_buf        = iface->eq_grow.pending_buf;
    iface->eq_md          = iface->eq_grow.pending_md;
    iface->eq_num_events = (unsigned)(iface->eq_grow.pending_len /
                                      UCT_CXI_EQ_ENTRY_SIZE);
    iface->eq_grow.pending_buf = NULL;
    iface->eq_grow.pending_md  = NULL;
    iface->eq_grow.pending_len = 0;
    iface->eq_grow.resizing    = 0;

    target_reserved = (iface->eq_num_events *
                       iface->eq_reserved_slots_pct) / 100;
    ret = cxil_evtq_adjust_reserved_fc(
            iface->evtq, (int)target_reserved - (int)iface->eq_reserved_slots);
    if (ret < 0) {
        ucs_warn("cxi EQ grow: reserved-slots adjust failed: %s — "
                 "reserved floor now a smaller fraction of the grown EQ",
                 strerror(-ret));
    } else {
        iface->eq_reserved_slots = (unsigned)ret;
    }

    ucs_debug("cxi EQ grown: now %u events", iface->eq_num_events);
}

static unsigned uct_cxi_iface_progress(uct_iface_h tl_iface)
{
    uct_cxi_iface_t     *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    const union c_event *event;
    uct_cxi_send_op_t   *op;
    unsigned             n = 0;

    /* Bounded per the EQ_MAX_POLL doc — a steady flood must not keep this
     * loop running past the point where the post-loop EQ_DYNAMIC_GROWTH
     * fill-threshold and EQ_DRAIN_PCT drop checks below would still have
     * time to act; matches every other UCX transport's poll-a-bounded-
     * batch-and-return pattern (RC/UD/DC's TX/RX_MAX_POLL, TCP's
     * UCT_TCP_MAX_EVENTS) rather than draining to empty. */
    while ((n < iface->eq_max_poll) &&
           ((event = cxi_eq_get_event(iface->evtq)) != NULL)) {
        if ((event->hdr.event_type == C_EVENT_REPLY) &&
            event->init_short.rendezvous) {
            /* NIC-auto-issued (get_issued==1) rendezvous Get completed.
             * user_ptr here is not a pointer -- it's a bit-packed struct
             * cxi_rdzv_user_ptr, not something the generic op-based
             * dispatch below can touch at all -- see
             * uct_cxi_iface_tag_handle_rdzv_reply's own doc comment
             * (cxi_tag.c). */
            uct_cxi_iface_tag_handle_rdzv_reply(iface, event);
        } else if (event->hdr.event_type == C_EVENT_ACK  ||
            event->hdr.event_type == C_EVENT_REPLY) {
            /* Initiator-side TX completion.
             * ACK   = restricted PUT confirmed by remote (RMA).
             * REPLY = GET data returned (RMA, or a software-issued
             *         get_issued==0 rendezvous Get -- see below). */
            op = (uct_cxi_send_op_t *)(uintptr_t)event->init_short.user_ptr;
            if (op->ep == NULL) {
                /* Software-issued rendezvous Get (uct_cxi_rdzv_get_op_t,
                 * see uct_cxi_iface_issue_rdzv_get in cxi_tag.c) --
                 * deliberately has no uct_cxi_ep_t (tag receives are
                 * posted on the iface, not a specific peer), so none of
                 * the ep-bookkeeping below applies; dispatch straight to
                 * its handler. No other op type in this transport ever
                 * has ep==NULL. */
                ucs_status_t status = uct_cxi_rc_to_status(cxi_event_rc(event));
                op->handler(op, status);
            } else {
                ucs_status_t status = uct_cxi_rc_to_status(cxi_event_rc(event));

                if (ucs_unlikely(status != UCS_OK)) {
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
                /* Target PTE in graceful recovery (en_flowctrl) or any
                 * other completion status feeds this EP's adaptive
                 * concurrency cap / retry cadence — see
                 * uct_cxi_ep_tx_complete(). No wire message needed: this
                 * is a purely local, self-observed signal. */
                uct_cxi_ep_tx_complete(op->ep, status);
                /* Latch the worst status seen across every op draining
                 * while a flush is pending on this EP — first failure
                 * sticks (uct_completion_update_status). The final
                 * uct_invoke_completion(..., UCS_OK) below is safe
                 * regardless: it internally re-applies update_status,
                 * which UCS_OK can never overwrite an already-latched
                 * error with. */
                if (op->ep->flush_comp != NULL) {
                    uct_completion_update_status(op->ep->flush_comp, status);
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
                    op->handler(op, status); /* bcopy: handler owns comp + mpool_put */
                } else {
                    if (op->comp != NULL) {
                        uct_invoke_completion(op->comp, status);
                    }
                    ucs_mpool_put(op);     /* zcopy / short */
                }
            }
        } else if ((event->hdr.event_type == C_EVENT_RENDEZVOUS) &&
                   (iface->tag.pte != NULL) &&
                   (event->tgt_long.ptlte_index == iface->tag.pte->ptn)) {
            /* Direct-matched rendezvous Put (Phase B) -- always on the
             * priority list (an unexpected rendezvous arrival stays
             * C_EVENT_PUT/ptl_list==OVERFLOW, handled by the branch
             * below). Joins tag_handle_rndv_match's 3-event completion
             * accounting -- see its doc comment. */
            uct_cxi_iface_tag_handle_rndv_match(iface, event);
        } else if ((event->hdr.event_type == C_EVENT_GET) &&
                   (iface->rdzv.pte != NULL) &&
                   (event->tgt_long.ptlte_index == iface->rdzv.pte->ptn)) {
            /* A peer's Get read from our exposed rendezvous catch-all LE
             * -- the send side of a rendezvous transfer completing. */
            uct_cxi_iface_tag_handle_rdzv_get(iface, event);
        } else if ((event->hdr.event_type == C_EVENT_PUT) &&
                   (iface->tag.pte != NULL) &&
                   (event->tgt_long.ptlte_index == iface->tag.pte->ptn)) {
            /* Target-side TAG receive.  Both LE populations on this PTE
             * report C_EVENT_PUT; ptl_list is the discriminator (shared
             * ptlte_index alone can't tell them apart) -- see cxi_tag.h.
             * A direct-matched rendezvous Put's eager-attached prefix
             * also lands here (ptl_list==PRIORITY, event->tgt_long.
             * rendezvous==1) alongside its own separate C_EVENT_RENDEZVOUS
             * above -- route by that flag, not just ptl_list. */
            if (event->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) {
                uct_cxi_iface_tag_handle_ovf_arrival(iface, event);
            } else if (event->tgt_long.rendezvous) {
                uct_cxi_iface_tag_handle_rndv_match(iface, event);
            } else {
                uct_cxi_iface_tag_handle_eager_match(iface, event);
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

            uct_iface_invoke_am(&iface->super, am_id, data, len, 0);

            if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
                /* This Put exhausted the buffer's remaining space and
                 * triggered auto-unlink as a side effect (min_free).  EQ
                 * delivery is ordered, so this is guaranteed to be the
                 * last Put for this buffer generation — safe to repost
                 * right here, no separate tracking needed.  (The genuine
                 * C_EVENT_UNLINK below only fires for explicit/manual
                 * unlinks, e.g. teardown — it never drives repost.) */
                uct_cxi_iface_post_am_le(iface, buf_idx, 1);
            }

        } else if (event->hdr.event_type == C_EVENT_STATE_CHANGE) {
            /* Two distinct things produce this event, and ptlte_state alone
             * cannot tell them apart — both report DISABLED identically:
             *   - A fresh, NIC-initiated disable (return_code == C_RC_OK).
             *   - The completion of our *own* SETSTATE(ENABLED) attempt,
             *     rejected (C_RC_NO_MATCH) if drop_count moved between our
             *     cxil_pte_status() read and the command actually landing
             *     in hardware — a real race at sustained high message
             *     rates, not a bug in the read/issue sequence. sc_reason
             *     is not meaningful on a rejection completion (observed:
             *     nonsensical values outside the documented enum) — only
             *     return_code distinguishes the two cases. */
            uint8_t  ptlte_state =
                    event->tgt_long.initiator.state_change.ptlte_state;
            uint8_t  sc_reason =
                    event->tgt_long.initiator.state_change.sc_reason;
            int      rc          = cxi_event_rc(event);
            uint16_t ptlte_index = event->tgt_long.ptlte_index;

            ucs_warn("cxi PTE state change: ptn=%u ptlte_state=%u "
                     "sc_reason=%u sc_nic_auto=%u rc=%d",
                     (unsigned)ptlte_index,
                     (unsigned)ptlte_state, (unsigned)sc_reason,
                     (unsigned)event->tgt_long.initiator.state_change.sc_nic_auto,
                     rc);

            if (rc != C_RC_OK) {
                /* Our own SETSTATE(ENABLED) was rejected — drop_count
                 * moved between our cxil_pte_status() read and the
                 * command landing in hardware (a real race at sustained
                 * high message rates). This is NOT caused by EQ
                 * pressure — the rejection generates no EQ traffic of
                 * its own — so retry immediately with a fresh read
                 * rather than waiting on drain progress that has
                 * nothing to do with this PTE's drop_count. */
                struct cxil_pte  *pte;
                uct_cxi_pte_fc_t *fc = uct_cxi_iface_pte_by_index(
                        iface, ptlte_index, &pte);
                if (fc != NULL) {
                    uct_cxi_iface_pte_recover(iface, pte, fc);
                }
            } else if (ptlte_state == C_PTLTE_DISABLED) {
                if (sc_reason == C_SC_FC_EQ_FULL) {
                    /* Fresh disable caused by EQ capacity — iface-wide:
                     * every PTE and every initiator-side completion
                     * shares this ring. Defer recovery until the EQ has
                     * actually drained (see the eq_need_to_drain
                     * countdown below) rather than retrying inline. */
                    if (iface->eq_need_to_drain == 0) {
                        iface->eq_need_to_drain = (iface->eq_num_events *
                                                   iface->eq_drain_pct) / 100;
                    }
                } else if ((iface->am.pte != NULL) &&
                           (ptlte_index == iface->am.pte->ptn)) {
                    /* Fresh disable for a non-EQ-capacity reason on the
                     * AM PTE — matching-resource exhaustion (N=4 fixed
                     * rotating buffers all simultaneously full; RMA/AMO
                     * can't reach this path, see uct_cxi_pte_fc_t).
                     * Independent of EQ-fill: gate new AM sends via
                     * am.fc.exhausted (uct_cxi_ep_fc_blocked) and
                     * attempt recovery right away rather than waiting on
                     * drain progress, which doesn't free buffer/LE
                     * capacity. */
                    iface->am.fc.exhausted = 1;
                    uct_cxi_iface_pte_recover(iface, iface->am.pte,
                                              &iface->am.fc);
                }
            } else if (ptlte_state == C_PTLTE_ENABLED) {
                /* Successful re-enable clears matching-resource
                 * EXHAUSTED for the AM PTE. (DRAINING clears separately
                 * via eq_need_to_drain reaching 0, not here.) */
                if ((iface->am.pte != NULL) &&
                    (ptlte_index == iface->am.pte->ptn)) {
                    iface->am.fc.exhausted = 0;
                }
            }
        } else if ((event->hdr.event_type == C_EVENT_UNLINK) &&
                   (iface->tag.pte != NULL) &&
                   (event->tgt_long.ptlte_index == iface->tag.pte->ptn)) {
            uct_cxi_iface_tag_handle_unlink(iface, event);
        } else if (event->hdr.event_type == C_EVENT_UNLINK) {
            /* Auto-unlink (min_free) is signaled via auto_unlinked on the
             * triggering C_EVENT_PUT above, not via this event — that's
             * where repost happens.  A genuine C_EVENT_UNLINK here means
             * an explicit/manual unlink (e.g. teardown); nothing to
             * repost for those. */
            ucs_debug("cxi AM LE C_EVENT_UNLINK buf=%d (manual)",
                      (int)event->tgt_long.buffer_id);
        } else if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
                   (iface->tag.pte != NULL) &&
                   (event->tgt_long.ptlte_index == iface->tag.pte->ptn)) {
            /* Delayed correlation: this priority LE was posted after the
             * matching message had already landed in the overflow ring --
             * same disposition as a direct match, see cxi_tag.c. Route by
             * event->tgt_long.rendezvous the same way the direct-match
             * C_EVENT_PUT branch above does. */
            if (event->tgt_long.rendezvous) {
                uct_cxi_iface_tag_handle_rndv_match(iface, event);
            } else {
                uct_cxi_iface_tag_handle_eager_match(iface, event);
            }
        } else if (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) {
            ucs_info("cxi C_EVENT_PUT_OVERFLOW: ptl_list=%d am_id=%u "
                     "mlength=%u start=0x%lx remote_offset=0x%lx rc=%d",
                     (int)event->tgt_long.ptl_list,
                     (unsigned)(event->tgt_long.match_bits & 0x1f),
                     (unsigned)event->tgt_long.mlength,
                     (unsigned long)event->tgt_long.start,
                     (unsigned long)event->tgt_long.remote_offset,
                     cxi_event_rc(event));
        } else if (event->hdr.event_type == C_EVENT_EQ_SWITCH) {
            /* Last event hardware writes to the old buffer of a
             * preemptive resize (see uct_cxi_iface_eq_grow_start) —
             * switch reading to the new buffer. */
            uct_cxi_iface_eq_grow_complete(iface);
        } else {
            ucs_info("cxi iface_progress: unhandled event type %d rc=%d",
                     (int)event->hdr.event_type, cxi_event_rc(event));
        }
        n++;

        /* Draining back down after a drop (see below) — count every event
         * processed here, since it's already being iterated; no extra
         * hardware query needed. Real events are frequently smaller than
         * the worst-case 64 bytes eq_num_events is sized around (e.g.
         * C_EVENT_ACK/REPLY use the ~32-byte short format), so counting
         * against that conservative unit only ever under-counts how much
         * room was actually freed — safe in the conservative direction.
         * At the threshold, check PTE status and recover anything found
         * disabled; re-enabling immediately on every drop instead would
         * just re-trigger the same disable on the next blocked event
         * under sustained pressure. */
        if ((iface->eq_need_to_drain > 0) &&
            (--iface->eq_need_to_drain == 0)) {
            uct_cxi_iface_recover_ptes(iface);
        }
    }

    if (ucs_unlikely(cxi_eq_get_drops(iface->evtq))) {
        ucs_error("cxi EQ drop detected: events lost (EQ full)");
        if (iface->eq_need_to_drain == 0) {
            iface->eq_need_to_drain = (iface->eq_num_events *
                                       iface->eq_drain_pct) / 100;
        }
        cxi_eq_ack_drops(iface->evtq);
    }

    /* Preemptive growth: cheap, timestamp-gated fast path (returns 0
     * immediately when nothing has changed since the last check) — see
     * uct_cxi_iface_eq_grow_start(). Independent of the reactive drop
     * handling above; both may fire in the same iface's lifetime without
     * coupling. */
    if (iface->eq_grow.enabled && !iface->eq_grow.resizing) {
        struct c_eq_status eq_status;

        if (cxi_eq_get_status(iface->evtq, &eq_status) &&
            eq_status.thld_sts &&
            (cxi_eq_status_fill_level(iface->evtq, &eq_status) >=
                    iface->eq_grow.thresh_pct)) {
            uct_cxi_iface_eq_grow_start(iface);
        }
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
