/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload -- Phase A (eager) + Phase B
 * (native, direct-match-only rendezvous; see the design plan's "Current
 * increment").
 *
 * PTE layout: one PTE (pid_offset = UCT_CXI_PTE_TAG), is_matching=1,
 * use_long_event=1 -- structurally like the AM PTE, but genuinely
 * exploiting Cassini's matching (sender's tag in match_bits, not always
 * wildcarded like AM). Two independent LE populations share it:
 *
 *   - Priority-list LEs, one per uct_iface_tag_recv_zcopy() call, use_once,
 *     bound directly to the caller's own registered destination buffer:
 *     a direct match DMAs straight into it with zero software copy.
 *   - A true Portals4 overflow-list ring (C_PTL_LIST_OVERFLOW,
 *     unexpected_hdr_disable=0), catching messages that arrive with no
 *     matching priority LE posted yet. Unlike the AM ring (which never
 *     uses real overflow-list semantics at all, see cxi_iface.c), data
 *     landing here is copied out and handed to UCP's own SW tag-matching
 *     immediately and unconditionally -- never retained waiting for a
 *     future post. This trades one extra copy (vs. libfabric's
 *     retain-until-matched model) for a bounded, fast-draining overflow
 *     pool that can never accumulate an unbounded backlog.
 *
 * Send side: all three eager variants (short/bcopy/zcopy) produce an
 * identical wire Put via ep->dfa_tag (unrestricted, no rkey) -- Cassini's
 * target-side matching can't distinguish an IDC-inline send from a
 * bounce-buffer DMA from a direct-buffer DMA. imm always travels via
 * header_data (tag has no am_id to share the field with, unlike AM).
 *
 * Repost/cancel timing -- see the design discussion this was built from:
 *   - Overflow-ring repost is driven by auto_unlinked on the ring's own
 *     terminal C_EVENT_PUT (same fix validated for the AM ring), not by
 *     C_EVENT_UNLINK, which arrives too early (before the triggering Put
 *     is even fully processed) to use as a repost trigger.
 *   - A priority-LE slot is freed on the first genuine disposition event:
 *     a match (C_EVENT_PUT with ptl_list==PRIORITY, or C_EVENT_PUT_OVERFLOW),
 *     or C_EVENT_UNLINK with return_code==C_RC_OK. A cancel racing a
 *     winning match produces a second, self-identifying event --
 *     C_EVENT_UNLINK with C_RC_ENTRY_NOT_FOUND -- dropped unconditionally,
 *     no separate "owed event count" tracking needed (validated against
 *     libfabric's own cxip_evtq_event_req() handling of this exact race).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_tag.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_iov.inl>
#include <ucs/debug/log.h>
#include <ucs/sys/math.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_tag_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

/* Plain host-memory pool -- no DMA registration needed, data is always
 * copied out of the overflow ring via memcpy before this pool is touched. */
static ucs_mpool_ops_t uct_cxi_tag_unexp_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL,
    .obj_str       = NULL
};


/* -------------------------------------------------------------------------
 * PTE lifecycle
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_iface_post_tag_ovf_le -- append one overflow-list LE for ring
 * buffer buf_idx. Mirrors uct_cxi_iface_post_am_le's shape (contiguous
 * ring, buffer_id-indexed, manage_local), but with the flags that make
 * this a genuine Portals4 overflow list -- see file header.
 */
static ucs_status_t
uct_cxi_iface_post_tag_ovf_le(uct_cxi_iface_t *self, int buf_idx,
                              int restart_seq)
{
    struct c_target_cmd le = {};
    int                 ret;

    le.command.opcode         = C_CMD_TGT_APPEND;
    le.ptl_list               = C_PTL_LIST_OVERFLOW;
    le.ptlte_index            = self->tag.pte->ptn;
    le.op_put                 = 1;
    le.op_get                 = 0;
    le.use_once               = 0;
    le.manage_local           = 1;
    le.unrestricted_body_ro   = 1;
    le.unrestricted_end_ro    = 1;
    le.event_link_disable     = 1;
    le.event_unlink_disable   = 1; /* repost driven by auto_unlinked on the
                                     * terminal C_EVENT_PUT, not this event
                                     * -- see tag_handle_ovf_arrival() */
    le.no_truncate            = 1; /* reject oversized unexpected messages
                                     * rather than silently truncate */
    le.unexpected_hdr_disable = 0; /* real overflow-list semantics -- see
                                     * file header */
    le.restart_seq            = restart_seq;
    le.match_id               = CXI_MATCH_ID_ANY;
    le.buffer_id              = (uint16_t)buf_idx;
    le.lac                    = self->tag.rx_mh.cxi_md->lac;
    le.start                  = self->tag.rx_mh.iova_offset +
                                (uint64_t)(uintptr_t)(self->tag.rx_base +
                                                       (size_t)buf_idx *
                                                       self->tag.buf_size);
    le.length                 = self->tag.buf_size;
    le.min_free               = UCT_CXI_TAG_OVF_MIN_FREE;
    le.ignore_bits            = UINT64_MAX;
    le.match_bits             = 0;

    ret = cxi_cq_emit_target(self->tgt.cmdq, &le);
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi TAG overflow LE APPEND buf %d: %d", buf_idx, ret);
        return UCS_ERR_IO_ERROR;
    }
    cxi_cq_ring(self->tgt.cmdq);
    ucs_debug("cxi TAG overflow LE APPEND buf=%d ptn=%u start=0x%lx "
             "len=%zu restart_seq=%d", buf_idx, self->tag.pte->ptn,
             (unsigned long)le.start, self->tag.buf_size, restart_seq);
    return UCS_OK;
}

ucs_status_t
uct_cxi_iface_open_tag_pte(uct_cxi_iface_t *self, struct cxil_lni *lni,
                           const uct_cxi_iface_config_t *config,
                           const uct_iface_params_t *params)
{
    const union c_event *ev;
    ucs_status_t         status;
    int                  ret;
    unsigned             i;

    memset(&self->tag, 0, sizeof(self->tag));

    if ((config->tag_enable == UCS_NO) ||
        !ucs_test_all_flags(params->field_mask,
                            UCT_IFACE_PARAM_FIELD_HW_TM_EAGER_CB |
                            UCT_IFACE_PARAM_FIELD_HW_TM_RNDV_CB)) {
        /* UCP didn't request HW tag offload (didn't supply both unexpected
         * callbacks), or the operator forced it off -- tag.pte stays NULL,
         * iface_query never advertises the TAG capability flags, and UCP
         * transparently falls back to SW tag matching over AM. Not an
         * error. */
        return UCS_OK;
    }

    self->tag.eager_cb  = params->eager_cb;
    self->tag.eager_arg = params->eager_arg;
    self->tag.rndv_cb   = params->rndv_cb;
    self->tag.rndv_arg  = params->rndv_arg;

    /* num_bufs must be clamped before max_outstanding is computed --
     * UCT_CXI_TAG_MAX_OUTSTANDING_MAX already reserves the buffer_id range
     * SEARCH_AND_DELETE needs (one id per overflow buffer, capped at
     * UCT_CXI_TAG_OVF_NUM_BUFS_MAX) below the hardware's real 65535
     * ceiling -- see UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE's doc comment
     * in cxi_tag.h for why that range exists. */
    self->tag.num_bufs        = ucs_min(config->tag_ovf_num_bufs,
                                        UCT_CXI_TAG_OVF_NUM_BUFS_MAX);
    self->tag.max_outstanding = ucs_min(config->tag_max_outstanding,
                                        UCT_CXI_TAG_MAX_OUTSTANDING_MAX);
    self->tag.buf_size        = ucs_max(config->tag_ovf_buf_size,
                                        config->tag_eager_max);

    /* Outstanding priority-LE tracking. */
    self->tag.ctx = ucs_calloc(self->tag.max_outstanding,
                               sizeof(*self->tag.ctx), "cxi-tag-ctx");
    if (self->tag.ctx == NULL) {
        return UCS_ERR_NO_MEMORY;
    }
    self->tag.free_list = ucs_malloc(self->tag.max_outstanding *
                                     sizeof(*self->tag.free_list),
                                     "cxi-tag-free-list");
    if (self->tag.free_list == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_ctx;
    }
    for (i = 0; i < self->tag.max_outstanding; i++) {
        self->tag.free_list[i] = (uint16_t)i;
    }
    self->tag.free_count = self->tag.max_outstanding;

    self->tag.cancel_ctx = ucs_calloc(self->tag.max_outstanding,
                                      sizeof(*self->tag.cancel_ctx),
                                      "cxi-tag-cancel-ctx");
    if (self->tag.cancel_ctx == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_free_list;
    }

    /* Per-peer unexpected-rndv header cache -- see uct_cxi_rndv_peer_hdr_t
     * in cxi_iface.h. Growable, starts empty; never fails to init. */
    kh_init_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);

    /* Unexpected-message copy-out pool: plain host memory (see
     * uct_cxi_tag_unexp_mpool_ops), sized to hold one full eager message. */
    {
        ucs_mpool_params_t mp_params;
        unsigned           grow = ucs_min(64u, config->tag_unexp_max_bufs);

        ucs_mpool_params_reset(&mp_params);
        mp_params.elem_size       = self->tag.buf_size;
        mp_params.elems_per_chunk = ucs_max(grow, 1u);
        mp_params.max_elems       = config->tag_unexp_max_bufs;
        mp_params.ops             = &uct_cxi_tag_unexp_mpool_ops;
        mp_params.name            = "cxi-tag-unexp";
        status = ucs_mpool_init(&mp_params, &self->tag.unexp_pool);
        if (status != UCS_OK) {
            goto err_free_rndv_peer_cache;
        }
    }

    /* Software-issued (get_issued==0) rendezvous Get tracking pool -- see
     * uct_cxi_rdzv_get_op_t in cxi_tag.h. Capped the same as
     * max_outstanding: never more outstanding software Gets than
     * outstanding priority-LE receives. */
    {
        ucs_mpool_params_t mp_params;
        unsigned           grow = ucs_min(64u, self->tag.max_outstanding);

        ucs_mpool_params_reset(&mp_params);
        mp_params.elem_size       = sizeof(uct_cxi_rdzv_get_op_t);
        mp_params.elems_per_chunk = ucs_max(grow, 1u);
        mp_params.max_elems       = self->tag.max_outstanding;
        mp_params.ops             = &uct_cxi_tag_unexp_mpool_ops;
        mp_params.name            = "cxi-tag-rdzv-get-op";
        status = ucs_mpool_init(&mp_params, &self->tag.rdzv_get_op_pool);
        if (status != UCS_OK) {
            goto err_cleanup_unexp_pool;
        }
    }

    /* Overflow ring: one contiguous allocation, single cxil_map -- same
     * shape as am.rx_base/am.rx_mh. */
    {
        size_t total = (size_t)self->tag.num_bufs * self->tag.buf_size;

        ret = ucs_posix_memalign((void **)&self->tag.rx_base,
                                 ucs_get_page_size(), total,
                                 "cxi-tag-rx-buf");
        if (ret != 0) {
            status = UCS_ERR_NO_MEMORY;
            goto err_cleanup_unexp_pool;
        }
        status = uct_cxi_do_map(lni, self->tag.rx_base, total,
                                UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
                                &self->tag.rx_mh);
        if (status != UCS_OK) {
            ucs_free(self->tag.rx_base);
            self->tag.rx_base = NULL;
            goto err_cleanup_unexp_pool;
        }
    }

    /* One ref-count/repost-pending slot per overflow buffer generation --
     * see cxi_iface.h's doc comment on ovf_refcnt. */
    self->tag.ovf_refcnt = ucs_calloc(self->tag.num_bufs,
                                      sizeof(*self->tag.ovf_refcnt),
                                      "cxi-tag-ovf-refcnt");
    if (self->tag.ovf_refcnt == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_unmap_rx;
    }
    self->tag.ovf_repost_pending = ucs_calloc(
            self->tag.num_bufs, sizeof(*self->tag.ovf_repost_pending),
            "cxi-tag-ovf-repost-pending");
    if (self->tag.ovf_repost_pending == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_ovf_refcnt;
    }

    {
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,
            .use_long_event = 1,
            .en_flowctrl    = 1
        };
        ret = cxil_alloc_pte(lni, self->evtq, &pt_opts, &self->tag.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte TAG: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_rx;
    }

    ret = cxil_map_pte(self->tag.pte, self->domain, (int)UCT_CXI_PTE_TAG,
                       false, &self->tag.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte TAG: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pte;
    }

    /* Transition PTE DISABLED -> ENABLED; spin for STATE_CHANGE event. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = self->tag.pte->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi TAG SETSTATE: %d", ret);
            status = UCS_ERR_IO_ERROR;
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

    /* Post all overflow-ring buffers -- priority LEs are posted purely
     * on-demand, one per uct_iface_tag_recv_zcopy() call, never up front. */
    for (i = 0; i < self->tag.num_bufs; i++) {
        status = uct_cxi_iface_post_tag_ovf_le(self, (int)i, 0);
        if (status != UCS_OK) {
            goto err_unmap_pte;
        }
    }

    self->tag.enabled = 1;
    ucs_debug("cxi TAG PTE ptn %u enabled: %u overflow bufs x %zu bytes, "
             "max_outstanding=%u", self->tag.pte->ptn, self->tag.num_bufs,
             self->tag.buf_size, self->tag.max_outstanding);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(self->tag.pte_map);
    self->tag.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(self->tag.pte);
    self->tag.pte = NULL;
    ucs_free(self->tag.ovf_repost_pending);
    self->tag.ovf_repost_pending = NULL;
err_free_ovf_refcnt:
    ucs_free(self->tag.ovf_refcnt);
    self->tag.ovf_refcnt = NULL;
err_unmap_rx:
    uct_cxi_do_unmap(&self->tag.rx_mh);
    ucs_free(self->tag.rx_base);
    self->tag.rx_base = NULL;
    ucs_mpool_cleanup(&self->tag.rdzv_get_op_pool, 1);
err_cleanup_unexp_pool:
    ucs_mpool_cleanup(&self->tag.unexp_pool, 1);
err_free_rndv_peer_cache:
    kh_destroy_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
err_free_cancel_ctx:
    ucs_free(self->tag.cancel_ctx);
    self->tag.cancel_ctx = NULL;
err_free_free_list:
    ucs_free(self->tag.free_list);
    self->tag.free_list = NULL;
err_free_ctx:
    ucs_free(self->tag.ctx);
    self->tag.ctx = NULL;
    return status;
}

void uct_cxi_iface_close_tag_pte(uct_cxi_iface_t *self)
{
    int ret;

    if (!self->tag.enabled) {
        return;
    }

    if (self->tag.pte_map != NULL) {
        ret = cxil_unmap_pte(self->tag.pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte TAG failed: %s", strerror(-ret));
        }
    }
    if (self->tag.pte != NULL) {
        ret = cxil_destroy_pte(self->tag.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte TAG failed: %s", strerror(-ret));
        }
    }
    uct_cxi_do_unmap(&self->tag.rx_mh);
    ucs_free(self->tag.rx_base);
    ucs_free(self->tag.ovf_repost_pending);
    ucs_free(self->tag.ovf_refcnt);

    ucs_mpool_cleanup(&self->tag.rdzv_get_op_pool, 1);
    ucs_mpool_cleanup(&self->tag.unexp_pool, 1);
    kh_destroy_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
    ucs_free(self->tag.cancel_ctx);
    ucs_free(self->tag.free_list);
    ucs_free(self->tag.ctx);
}


/*
 * uct_cxi_iface_open_rdzv_pte -- rendezvous source-exposure PTE. Matching
 * mode (is_matching=1), one persistent whole-LAC catch-all LE spanning the
 * full address range, fully wildcarded (match_bits=0/ignore_bits=~0) --
 * same shape as libfabric's own DEFAULT rendezvous protocol source PTE
 * (cxip_rdzv_match_pte_alloc/cxip_rdzv_pte_src_req_alloc, cxip_rdzv_pte.c),
 * not the restricted/address-routed design this replaced. Matching mode
 * has nothing to disambiguate here (LAC-0-only) -- it exists purely so the
 * resulting Get lands on the wire format that actually carries match_bits,
 * which is how we get O(1) id-based correlation instead of an address
 * scan; see uct_cxi_rdzv_op_t's own comment in cxi_tag.h for the full
 * design and why the restricted approach doesn't work. Differs from a
 * "real" matching PTE like TAG/AM only in being op_get-only, no op_put
 * (nothing should ever Put to this PTE). LAC 0 only -- see the design
 * plan's Part 1 scoping. Called only when tag offload is enabled;
 * rendezvous has no meaning without it.
 */
ucs_status_t uct_cxi_iface_open_rdzv_pte(uct_cxi_iface_t *self,
                                         struct cxil_lni *lni)
{
    uct_cxi_md_t              *md = uct_cxi_iface_md(self);
    const union c_event       *ev;
    ucs_status_t               status;
    int                        ret;
    uint32_t                   i;

    memset(&self->rdzv, 0, sizeof(self->rdzv));

    self->rdzv.max_outstanding = ucs_min(self->tag.max_outstanding,
                                         UCT_CXI_RDZV_MAX_OUTSTANDING_MAX);
    self->rdzv.ops = ucs_calloc(self->rdzv.max_outstanding,
                               sizeof(*self->rdzv.ops), "cxi-rdzv-ops");
    if (self->rdzv.ops == NULL) {
        return UCS_ERR_NO_MEMORY;
    }
    self->rdzv.free_ids = ucs_malloc(self->rdzv.max_outstanding *
                                     sizeof(*self->rdzv.free_ids),
                                     "cxi-rdzv-free-ids");
    if (self->rdzv.free_ids == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_ops;
    }
    for (i = 0; i < self->rdzv.max_outstanding; i++) {
        self->rdzv.free_ids[i] = i;
    }
    self->rdzv.free_count = self->rdzv.max_outstanding;

    {
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching = 1,
            .en_flowctrl = 1
        };
        ret = cxil_alloc_pte(lni, self->evtq, &pt_opts, &self->rdzv.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte RDZV: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_free_ids;
    }

    /* pid_idx must be the device's own driver-reported rdzv_get_idx, not a
     * self-chosen value -- confirmed on real hardware (C_RC_PTLTE_NOT_FOUND
     * on every NIC-auto-issued Get's C_EVENT_REPLY) that a NIC-auto-issued
     * (get_issued==1) rendezvous Get targets this fixed, hardware-mandated
     * pid_idx unconditionally; it is not something software gets to choose,
     * unlike every other PTE in this transport. Matches libfabric's own
     * issue_rdzv_get()/cxip_rdzv_base_pte_alloc(), which both read
     * iface->dev->info.rdzv_get_idx for exactly this (cxip_msg_hpc.c:377,
     * cxip_rdzv_pte.c:290) -- this is a real hardware constraint, not a
     * wire-compatibility choice, so departing from it (as the original
     * design did, reasoning LAC-0-only scoping made libfabric's PTE mode
     * irrelevant) was wrong specifically here. */
    ret = cxil_map_pte(self->rdzv.pte, self->domain,
                       (int)md->cxi_dev->info.rdzv_get_idx, false,
                       &self->rdzv.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte RDZV: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pte;
    }

    /* Transition PTE DISABLED -> ENABLED; spin for STATE_CHANGE event. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = self->rdzv.pte->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi RDZV SETSTATE: %d", ret);
            status = UCS_ERR_IO_ERROR;
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

    /* Post the persistent whole-LAC catch-all LE, LAC 0 only. Fully
     * wildcarded (match_bits=0/ignore_bits=~0 -- nothing to disambiguate,
     * LAC-0-only) and unrestricted-flavored (unrestricted_body_ro/end_ro),
     * matching libfabric's own DEFAULT catch-all LE exactly
     * (cxip_rdzv_pte_src_req_alloc, cxip_rdzv_pte.c:78-123). */
    {
        struct c_target_cmd le = {};
        le.command.opcode        = C_CMD_TGT_APPEND;
        le.ptl_list              = C_PTL_LIST_PRIORITY;
        le.ptlte_index           = self->rdzv.pte->ptn;
        le.op_put                = 0;
        le.op_get                = 1;
        le.unrestricted_body_ro  = 1;
        le.unrestricted_end_ro   = 1;
        le.event_link_disable    = 1;
        le.event_unlink_disable  = 1;
        le.lac                   = 0;
        le.start                 = 0;
        le.length                = (1ULL << 56) - 1;
        le.match_id              = CXI_MATCH_ID_ANY; /* accept any initiator
                                   -- zero-init default targets one specific
                                   (bogus) identity instead, matching
                                   nothing; every other matching-mode LE in
                                   this transport (TAG, AM) already sets
                                   this */
        le.match_bits            = 0;
        le.ignore_bits           = UINT64_MAX;

        ret = cxi_cq_emit_target(self->tgt.cmdq, &le);
        if (ret != 0) {
            ucs_error("cxi RDZV APPEND LE: %d", ret);
            status = UCS_ERR_IO_ERROR;
            goto err_unmap_pte;
        }
        cxi_cq_ring(self->tgt.cmdq);
    }

    self->rdzv.enabled = 1;
    ucs_debug("cxi RDZV PTE ptn %u enabled", self->rdzv.pte->ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(self->rdzv.pte_map);
    self->rdzv.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(self->rdzv.pte);
    self->rdzv.pte = NULL;
err_free_ids:
    ucs_free(self->rdzv.free_ids);
    self->rdzv.free_ids = NULL;
err_free_ops:
    ucs_free(self->rdzv.ops);
    self->rdzv.ops = NULL;
    return status;
}

void uct_cxi_iface_close_rdzv_pte(uct_cxi_iface_t *self)
{
    int ret;

    if (!self->rdzv.enabled) {
        return;
    }

    if (self->rdzv.pte_map != NULL) {
        ret = cxil_unmap_pte(self->rdzv.pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte RDZV failed: %s", strerror(-ret));
        }
    }
    if (self->rdzv.pte != NULL) {
        ret = cxil_destroy_pte(self->rdzv.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte RDZV failed: %s", strerror(-ret));
        }
    }
    ucs_free(self->rdzv.free_ids);
    self->rdzv.free_ids = NULL;
    ucs_free(self->rdzv.ops);
    self->rdzv.ops = NULL;
}


/* -------------------------------------------------------------------------
 * Event dispatch (called from cxi_iface.c's iface_progress())
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_iface_tag_ovf_buf_idx / uct_cxi_iface_tag_ovf_data -- shared
 * address-range math for locating which overflow ring buffer an event's
 * event->tgt_long.start falls within, and the actual data pointer inside
 * it. Used both for a fresh arrival (buf_idx already known directly from
 * buffer_id there) and, more importantly, for a *later* confirmation event
 * (SEARCH_AND_DELETE completion, or a real delayed match) that only
 * carries the address, not which ring slot it originated from.
 */
static inline int
uct_cxi_iface_tag_ovf_buf_idx(uct_cxi_iface_t *iface, uint64_t start)
{
    uint64_t base_iova = iface->tag.rx_mh.iova_offset +
                         (uint64_t)(uintptr_t)iface->tag.rx_base;

    return (int)((start - base_iova) / iface->tag.buf_size);
}

static inline void *
uct_cxi_iface_tag_ovf_data(uct_cxi_iface_t *iface, int buf_idx,
                           uint64_t start)
{
    uint8_t *buf_va   = iface->tag.rx_base +
                        (size_t)buf_idx * iface->tag.buf_size;
    uint64_t buf_iova = iface->tag.rx_mh.iova_offset +
                        (uint64_t)(uintptr_t)buf_va;

    return buf_va + (size_t)(start - buf_iova);
}

/*
 * uct_cxi_iface_tag_ovf_release -- drop one reference on an overflow
 * buffer generation (see cxi_iface.h's doc comment on ovf_refcnt). Call
 * only when the event resolving a given arrival has that arrival's own
 * mlength>0 (mirroring tag_handle_ovf_arrival()'s increment condition --
 * an mlength==0 arrival never took a reference to begin with), from
 * whichever handler is the actual, sole reader of that arrival's own
 * overflow-buffer memory: tag_handle_search_delete_confirm_eager()/_rndv()
 * when our own SEARCH_AND_DELETE finds and deletes it (it does the copy,
 * so it releases); tag_handle_eager_match()/tag_handle_rdzv_match() when a
 * real priority-LE delayed match wins instead (same reasoning, they do the
 * copy) -- including their force-cancel branches, which release directly
 * since the normal copy-then-release path never runs once cancelled.
 * Never tag_handle_search_delete_not_found() -- that event carries no
 * data-read obligation of its own (nothing there ever touches
 * overflow-buffer memory), so it must never gate reposting.
 *
 * Relies on this arrival's own raw C_EVENT_PUT always being delivered
 * before whatever event later resolves it (a real delayed match, or our
 * own SEARCH_AND_DELETE outcome) -- i.e. the increment here always
 * precedes the corresponding decrement. This transport already depends on
 * that same EQ-ordering guarantee elsewhere, so it is assumed rather than
 * defended against a second time; the assert below is the safety net if
 * it's ever violated.
 */
static void
uct_cxi_iface_tag_ovf_release(uct_cxi_iface_t *iface, int buf_idx)
{
    ucs_assertv(iface->tag.ovf_refcnt[buf_idx] > 0, "buf_idx=%d", buf_idx);
    if ((--iface->tag.ovf_refcnt[buf_idx] == 0) &&
        iface->tag.ovf_repost_pending[buf_idx]) {
        iface->tag.ovf_repost_pending[buf_idx] = 0;
        uct_cxi_iface_post_tag_ovf_le(iface, buf_idx, 1);
    }
}

/*
 * uct_cxi_iface_tag_handle_search_delete_confirm_eager -- the "found and
 * deleted" confirmation for our own SEARCH_AND_DELETE: a
 * C_EVENT_PUT_OVERFLOW on the tag PTE whose buffer_id falls in the
 * reserved SEARCH_AND_DELETE range (see UCT_CXI_TAG_SEARCH_DELETE_
 * BUFIDX_BASE's doc comment in cxi_tag.h). Dispatched directly from
 * cxi_iface.c's progress loop -- checked once, before ever choosing
 * between eager and rendezvous match handling, rather than duplicated
 * inside both (or relying on uct_cxi_iface_tag_match_lookup()'s ordinary
 * bounds check to coincidentally also catch it, which said nothing about
 * *why* it's safe to drop and left tag_handle_rdzv_match() with no
 * explicit handling of this case at all -- SEARCH_AND_DELETE is only ever
 * issued for eager unexpected arrivals, so this event is never
 * rendezvous-flagged and tag_handle_rdzv_match() should never need to
 * know it exists).
 *
 * With sd.use_once=1 (see tag_handle_ovf_arrival()'s own comment on that
 * flag), this event type only ever fires for the "found and deleted"
 * outcome -- confirmed on real hardware (cxi_event_rc()==C_RC_OK on every
 * observed run, test_cxi_tag_ovf.raw_event_order_and_manual_search_
 * delete). The "not found" outcome is a structurally different event
 * type entirely (C_EVENT_SEARCH, handled by tag_handle_search_delete_
 * not_found() below), not a different rc on this same event -- so unlike
 * the pre-use_once design, there is no second outcome to branch on here;
 * a non-OK rc on this event type would be a genuine surprise, logged
 * defensively but not otherwise expected to occur.
 *
 * buf_idx comes directly from the event's own buffer_id (buffer_id -
 * BUFIDX_BASE), not from event->tgt_long.start -- start is still needed
 * separately, for its real purpose: locating the actual bytes to copy
 * within the overflow buffer (SEARCH_AND_DELETE only removes the list
 * *entry*, it has no destination-address field of its own to move data
 * with -- confirmed against every libfabric SEARCH/SEARCH_AND_DELETE call
 * site). This is the only event that will ever fire for this specific
 * arrival (real hardware search-on-append can never also independently
 * claim an entry our own use_once=1 SEARCH_AND_DELETE already found and
 * deleted), so this is also where the arrival's own overflow-buffer
 * reference is released.
 */
void
uct_cxi_iface_tag_handle_search_delete_confirm_eager(uct_cxi_iface_t *iface,
                                               const union c_event *event)
{
    int      buf_idx = (int)event->tgt_long.buffer_id -
                       UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE;
    uint32_t len      = event->tgt_long.mlength;
    uint64_t tag      = event->tgt_long.match_bits;
    uint64_t imm      = event->tgt_long.header_data;
    void    *data;
    void    *elem;
    void    *context = NULL;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /* Not expected to be reachable with use_once=1 -- see this
         * function's own doc comment. Still release rather than leak if
         * it ever is; there is no companion event to fall back on for
         * this buf_idx otherwise. Guarded on len>0 like every other release
         * here -- a reference was only ever taken for this arrival if its
         * own mlength was >0 (see ovf_refcnt's doc comment in cxi_iface.h),
         * and len is that same mlength. */
        ucs_error("cxi TAG [SEARCH-DELETE-UNEXPECTED-RC] tag=0x%lx rc=%d "
                 "buf_idx=%d -- C_EVENT_PUT_OVERFLOW with use_once=1 "
                 "reported a non-OK rc, which real-hardware testing never "
                 "observed; releasing anyway", (unsigned long)tag,
                 cxi_event_rc(event), buf_idx);
        if (len > 0) {
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        return;
    }

    /* Copy out before releasing the reference below -- releasing first
     * can trigger a repost (uct_cxi_iface_post_tag_ovf_le()), making this
     * exact memory eligible for the NIC to overwrite with a new arrival
     * before we've read it. */
    data = uct_cxi_iface_tag_ovf_data(iface, buf_idx, event->tgt_long.start);
    elem = (len > 0) ? ucs_mpool_get(&iface->tag.unexp_pool) : NULL;
    if (ucs_unlikely((elem == NULL) && (len > 0))) {
        ucs_error("cxi TAG overflow: unexp_pool exhausted, dropping "
                 "unexpected message tag=0x%lx len=%u",
                 (unsigned long)tag, len);
        uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        return;
    }
    if (len > 0) {
        memcpy(elem, data, len);
        uct_cxi_iface_tag_ovf_release(iface, buf_idx);
    }

    ucs_info("cxi TAG [SEARCH-DELETE-MATCH] tag=0x%lx len=%u buf_idx=%d",
             (unsigned long)tag, len, buf_idx);

    /* No UCT_CB_PARAM_FLAG_DESC offered -- eager_cb must copy out
     * synchronously if it wants to keep the data, matching this same
     * transport's existing AM convention. We reclaim our own buffer right
     * away regardless of the returned status. */
    (void)iface->tag.eager_cb(iface->tag.eager_arg, elem, len,
                              UCT_CB_PARAM_FLAG_FIRST, tag, imm, &context);
    if (elem != NULL) {
        ucs_mpool_put(elem);
    }
}

/*
 * uct_cxi_iface_tag_handle_search_delete_not_found -- "not found" for our
 * own SEARCH_AND_DELETE (eager or rendezvous -- buffer_id tells us which
 * range, and the disposition is identical either way): hardware's own
 * search-on-append already claimed this arrival via the ordinary
 * priority-LE path instead. event->tgt_long.start is always 0 on this
 * event type (confirmed on real hardware), so buf_idx comes from
 * buffer_id, not from address math. Nothing to copy or report -- the real
 * match already delivered the data through its own, independent path.
 *
 * Deliberately does NOT call uct_cxi_iface_tag_ovf_release() -- this event
 * never reads this arrival's overflow-buffer memory, so it must not decide
 * when that memory becomes safe to repost either. The real delayed-match
 * handler that wins this race (tag_handle_eager_match() or
 * tag_handle_rdzv_match()) always fires for this same arrival exactly once
 * (use_once=1 guarantees this "not found" outcome only occurs when a real
 * priority LE independently claimed it) and releases the reference itself,
 * after it finishes reading. See uct_cxi_iface_tag_ovf_release()'s own doc
 * comment for the bug this fixes.
 */
void
uct_cxi_iface_tag_handle_search_delete_not_found(uct_cxi_iface_t *iface,
                                                 const union c_event *event)
{
    int is_rndv = event->tgt_long.buffer_id >=
                  UCT_CXI_TAG_SEARCH_DELETE_RNDV_BUFIDX_BASE;
    int buf_idx = (int)event->tgt_long.buffer_id -
                  (is_rndv ? UCT_CXI_TAG_SEARCH_DELETE_RNDV_BUFIDX_BASE :
                             UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE);

    ucs_info("cxi TAG [SEARCH-DELETE-NOT-FOUND%s] buf_idx=%d rc=%d "
             "match_bits=0x%lx", is_rndv ? "-RNDV" : "", buf_idx,
             cxi_event_rc(event), (unsigned long)event->tgt_long.match_bits);
}

/*
 * uct_cxi_iface_tag_handle_search_delete_confirm_rndv -- rendezvous
 * counterpart of tag_handle_search_delete_confirm_eager() above (buffer_id in the
 * disjoint RNDV range). No payload to copy -- a rendezvous message's data
 * is pulled later by UCP's own generic Get, not delivered inline. This just
 * hands rndv_cb what that Get needs:
 *   - header/header_length: the real eager-attached bytes for a "warm"
 *     arrival (mlength>0, cached here for any later "slim" one), or the
 *     cached prefix + this arrival's own header_data (req_id) for a "slim"
 *     one -- see uct_ep_tag_rndv_zcopy's warm/slim design.
 *   - remote_addr = event->tgt_long.remote_offset directly (the sender's
 *     real source-buffer offset, not an RMA-style rkey-relative value).
 *   - rkey_buf: a stack uct_cxi_rkey_t with is_rndv=1 and rendezvous_id --
 *     enough for UCP's later uct_ep_get_zcopy/bcopy call to reach this
 *     transport's rendezvous source PTE via the same uct_ep, whose
 *     rem_nid/rem_pid already identify the peer. No real memory key exists
 *     to pack for this case.
 */
void
uct_cxi_iface_tag_handle_search_delete_confirm_rndv(uct_cxi_iface_t *iface,
                                                    const union c_event *event)
{
    int      buf_idx = (int)event->tgt_long.buffer_id -
                       UCT_CXI_TAG_SEARCH_DELETE_RNDV_BUFIDX_BASE;
    uint32_t mlength   = event->tgt_long.mlength;
    uint64_t tag       = event->tgt_long.match_bits;
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    uct_cxi_rndv_hdr_wire_t hdr;
    uct_cxi_rkey_t rkey = {};
    khiter_t k;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /* See tag_handle_search_delete_confirm_eager()'s own doc comment --
         * not expected to be reachable with use_once=1, but release rather
         * than leak if it ever is. Guarded on mlength>0: a reference was
         * only ever taken for this arrival if its own mlength was >0. */
        ucs_error("cxi TAG [SEARCH-DELETE-RNDV-UNEXPECTED-RC] tag=0x%lx "
                 "rc=%d buf_idx=%d", (unsigned long)tag,
                 cxi_event_rc(event), buf_idx);
        if (mlength > 0) {
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        return;
    }

    if (ucs_unlikely(mlength > 0)) {
        /* Warm: the real header is sitting in the overflow buffer -- read
         * it and cache {ep_id, md_index} for a later slim arrival. */
        void *data = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                event->tgt_long.start);
        int   ret;

        memcpy(&hdr, data, ucs_min(mlength, sizeof(hdr)));
        uct_cxi_iface_tag_ovf_release(iface, buf_idx);

        k = kh_put(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache,
                  initiator, &ret);
        if (ucs_likely(ret != UCS_KH_PUT_FAILED)) {
            kh_value(&iface->tag.rndv_peer_cache, k) =
                    (uct_cxi_rndv_peer_hdr_t){hdr.ep_id, hdr.md_index};
        }
    } else {
        /* Slim: reconstruct from this peer's cached {ep_id, md_index} plus
         * this arrival's own header_data (req_id). A cache miss should be
         * structurally impossible (the sender only goes slim after
         * confirming a completed round-trip) -- treat it as a hard error
         * rather than invent a header. */
        k = kh_get(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache,
                  initiator);
        if (ucs_unlikely(k == kh_end(&iface->tag.rndv_peer_cache))) {
            /* No release here -- mlength==0 (slim), so no reference was
             * ever taken for this arrival to begin with. */
            ucs_error("cxi TAG [SEARCH-DELETE-RNDV-NO-CACHE] tag=0x%lx "
                     "initiator=0x%x buf_idx=%d", (unsigned long)tag,
                     initiator, buf_idx);
            return;
        }
        hdr.ep_id    = kh_value(&iface->tag.rndv_peer_cache, k).ep_id;
        hdr.md_index = kh_value(&iface->tag.rndv_peer_cache, k).md_index;
        hdr.req_id   = event->tgt_long.header_data;
    }

    rkey.is_rndv       = 1;
    rkey.rendezvous_id = event->tgt_long.rendezvous_id;

    ucs_info("cxi TAG [SEARCH-DELETE-RNDV-MATCH] tag=0x%lx buf_idx=%d "
             "rlength=%u warm=%d rendezvous_id=%u", (unsigned long)tag,
             buf_idx, (unsigned)event->tgt_long.rlength, mlength > 0,
             (unsigned)rkey.rendezvous_id);

    /* flags=0 -- matches the reference HW-tag-offload transport
     * (uct_rc_mlx5_handle_unexp_rndv(), rc_mlx5_common.c), which passes a
     * literal 0 here; this transport never fragments a rendezvous
     * unexpected-arrival report across multiple callback invocations, so
     * there is no FIRST/LAST-style flag to set. */
    (void)iface->tag.rndv_cb(iface->tag.rndv_arg, 0, tag, &hdr, sizeof(hdr),
                             event->tgt_long.remote_offset,
                             event->tgt_long.rlength, &rkey);
}

/*
 * uct_cxi_iface_tag_handle_ovf_arrival -- an unexpected message landed in
 * the overflow ring (C_EVENT_PUT, ptl_list==C_PTL_LIST_OVERFLOW). Takes a
 * reference on the buffer generation when mlength>0 (see cxi_iface.h's
 * ovf_refcnt doc comment -- an mlength==0 arrival has no payload sitting in
 * this buffer for anything to read later, so nothing needs protecting) and
 * issues a targeted SEARCH_AND_DELETE against the unexpected list -- no
 * copy, no eager_cb here: this event alone can never tell whether
 * hardware's own search-on-append will independently win the same race (a
 * real priority LE could already be in flight on the same command queue),
 * so ownership isn't known until the SEARCH_AND_DELETE's own confirmation
 * (tag_handle_search_delete_confirm_eager() or tag_handle_search_
 * delete_not_found(), depending on outcome) resolves it. This is what
 * actually fixes the double-completion crash this increment exists for
 * (job 100716, ucp_request.inl:307): the old code handed off to eager_cb
 * immediately and unconditionally right here.
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    int      buf_idx = (int)event->tgt_long.buffer_id;
    uint64_t tag      = event->tgt_long.match_bits;
    struct c_target_cmd sd = {};
    int      ret;

    if (event->tgt_long.mlength > 0) {
        iface->tag.ovf_refcnt[buf_idx]++;
    }
    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        /* EQ delivery is ordered, so this Put is guaranteed to be the
         * last one for this buffer generation -- see file header. Record
         * that a repost is owed once every message in this generation
         * (this one included) has actually been resolved; do not repost
         * yet -- an earlier, still-unresolved message in the same
         * generation would have its memory reused out from under it. */
        iface->tag.ovf_repost_pending[buf_idx] = 1;
    }

    ucs_info("cxi TAG [OVF-ARRIVAL] buf_idx=%d tag=0x%lx mlength=%u "
             "rlength=%u start=0x%lx auto_unlinked=%u", buf_idx,
             (unsigned long)tag, (unsigned)event->tgt_long.mlength,
             (unsigned)event->tgt_long.rlength,
             (unsigned long)event->tgt_long.start,
             (unsigned)event->tgt_long.auto_unlinked);

    /* Targets C_PTL_LIST_UNEXPECTED, not OVERFLOW -- confirmed against
     * every libfabric SEARCH/SEARCH_AND_DELETE call site, all of which
     * target UNEXPECTED exclusively; OVERFLOW is just the receive-buffer
     * list, UNEXPECTED is the actual search-on-append-visible tracking
     * list. match_id must be CXI_MATCH_ID_ANY, not zero-init, to be a real
     * wildcard (a genuine, previously-hit bug: zero-init only matches one
     * specific bogus initiator identity). length must be set too -- left
     * at its zero-init default, real hardware reported C_RC_NO_SPACE
     * (confirmed via debug logging, not a "not found" result at all): a
     * SEARCH command's length describes the region being searched, and 0
     * is a degenerate empty region, not "unbounded". Both of libfabric's
     * own SEARCH_AND_DELETE call sites (cxip_ux_onload(),
     * cxip_claim_ux_onload()) explicitly set this to -1U ("any address"
     * together with start's own zero-init default), never leave it at 0.
     *
     * use_once=1: found via libfabric's own cxip_claim_ux_onload()
     * (cxip_msg_hpc.c, "Delete first match") -- the actual analogue of
     * this exact use case (a targeted single-tag SEARCH_AND_DELETE, not a
     * wildcard onload). Without it, every SEARCH_AND_DELETE produces a
     * companion C_EVENT_SEARCH terminator in addition to the real outcome
     * -- confirmed on real hardware to disappear entirely with use_once=1
     * (test_cxi_tag_ovf.raw_event_order_and_manual_search_delete): a
     * "found and deleted" outcome now produces exactly one event
     * (C_EVENT_PUT_OVERFLOW, C_RC_OK), and a "not found" outcome produces
     * exactly one event too, just a different type (C_EVENT_SEARCH,
     * C_RC_NO_MATCH) -- never both for the same command. That turns what
     * was an unbounded, ordering-dependent correlation problem (which
     * arrival does a bare terminator belong to?) into a fixed, always-
     * exactly-one-event outcome per command.
     *
     * buffer_id encodes buf_idx directly (BUFIDX_BASE + buf_idx) rather
     * than a single shared sentinel -- see UCT_CXI_TAG_SEARCH_DELETE_
     * BUFIDX_BASE's own doc comment in cxi_tag.h for why: the "not found"
     * event's own event->tgt_long.start is always 0, not a real address,
     * so buf_idx cannot be recovered from the confirmation event's other
     * fields and has to be encoded into the one field we control.
     *
     * A rendezvous-flagged arrival (event->tgt_long.rendezvous==1) uses
     * the disjoint RNDV_BUFIDX_BASE range instead of the plain eager one
     * -- see that macro's own doc comment in cxi_tag.h -- so cxi_iface.c's
     * dispatch loop can route the resulting confirmation to
     * tag_handle_search_delete_confirm_rndv() (which calls rndv_cb, not
     * eager_cb) rather than the eager handler. This is the one place
     * eager and rendezvous unexpected arrivals diverge at all: everything
     * else about the SEARCH_AND_DELETE mechanics (ref-counting, use_once,
     * match_id/length wildcarding) is identical between the two. */
    sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
    sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    sd.ptlte_index    = iface->tag.pte->ptn;
    sd.match_bits     = tag;
    sd.ignore_bits    = 0;
    sd.match_id       = CXI_MATCH_ID_ANY;
    sd.length         = -1U;
    sd.use_once       = 1;
    sd.buffer_id      = (uint16_t)((event->tgt_long.rendezvous ?
                                    UCT_CXI_TAG_SEARCH_DELETE_RNDV_BUFIDX_BASE :
                                    UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE) +
                                   buf_idx);

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &sd);
    if (ucs_unlikely(ret != 0)) {
        /* Command-queue exhaustion -- rare, and there is no safe way to
         * confirm exclusive ownership without the SEARCH_AND_DELETE
         * actually landing, so the message is dropped rather than handed
         * off racily. Matches this function's own unexp_pool-exhaustion
         * precedent elsewhere in this file: rare-resource-pressure data
         * loss, not a new failure mode. */
        ucs_error("cxi TAG SEARCH_AND_DELETE emit failed: %d -- dropping "
                 "unexpected message tag=0x%lx", ret, (unsigned long)tag);
        if (event->tgt_long.mlength > 0) {
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        return;
    }
    cxi_cq_ring(iface->tgt.cmdq);
}

/*
 * uct_cxi_iface_issue_rdzv_get -- software-issued (get_issued==0) pull for
 * a direct-matched rendezvous receive. Unrestricted (matching-mode) DMA
 * GET -- restricted was tried first and confirmed not to work (see
 * uct_cxi_rdzv_op_t's doc comment in cxi_tag.h) -- targeting the sender's
 * dedicated rendezvous source PTE (at the device's rdzv_get_idx) instead
 * of its RMA PTE. The destination DFA is computed fresh from the event's
 * own initiator field (there is no uct_cxi_ep_t available here -- tag
 * receives are posted on the iface, not a specific peer -- see
 * cxi_dfa_nid/cxi_dfa_pid, the same decode libfabric itself uses on this
 * exact field, cxip_msg_hpc.c:182-184).
 *
 * cmd.match_bits carries the sender's own rendezvous op id straight
 * through from event->tgt_long.rendezvous_id (populated because our Put
 * is unrestricted) -- the sender reads it back off its own C_EVENT_GET to
 * do an O(1) lookup instead of a scan, DEFAULT-protocol style. See
 * uct_cxi_rdzv_op_t's doc comment in cxi_tag.h for the full design.
 *
 * local_addr skips past the eager-attached prefix already delivered
 * (event->tgt_long.start is the destination buffer's own base address,
 * fixed at the priority LE's own APPEND time, unrelated to how much of it
 * ended up delivered inline -- so + mlength lands the pull immediately
 * after the eager portion, mirroring issue_rdzv_get()'s own
 * local_addr = recv_buf_iova + rdzv_mlen, cxip_msg_hpc.c:416-418).
 *
 * user_ptr is a uct_cxi_rdzv_get_op_t (op first, matching
 * uct_cxi_send_desc_t's own precedent) so the existing, unmodified
 * C_EVENT_REPLY dispatch in cxi_iface.c's progress loop can drive its
 * completion through the ordinary op->handler path -- see
 * uct_cxi_rdzv_get_comp below.
 */
static ucs_status_t
uct_cxi_iface_issue_rdzv_get(uct_cxi_iface_t *iface,
                             const union c_event *event, uint16_t slot,
                             uint32_t posted_len)
{
    uct_cxi_md_t          *md = uct_cxi_iface_md(iface);
    uint32_t               init_dfa;
    uint32_t               sender_nid;
    uint32_t               sender_pid;
    union c_fab_addr       dfa;
    uint8_t                idx_ext;
    uint64_t               local_addr;
    uint32_t               data_len;
    uint32_t               request_len;
    uct_cxi_rdzv_get_op_t *rop;
    int                    ret;

    rop = (uct_cxi_rdzv_get_op_t *)ucs_mpool_get(&iface->tag.rdzv_get_op_pool);
    if (ucs_unlikely(rop == NULL)) {
        ucs_error("cxi TAG rdzv_get_op_pool exhausted, slot=%u", slot);
        return UCS_ERR_NO_RESOURCE;
    }
    rop->op.ep      = NULL;
    rop->op.comp    = NULL;
    rop->op.handler = uct_cxi_rdzv_get_comp;
    rop->iface      = iface;
    rop->slot       = slot;

    init_dfa   = event->tgt_long.initiator.initiator.process;
    sender_nid = cxi_dfa_nid(init_dfa);
    sender_pid = cxi_dfa_pid(init_dfa, md->pid_bits);
    /* pid_idx must be the sender's own driver-reported rdzv_get_idx, the
     * same fixed hardware-mandated value the NIC's own auto-issued Get
     * targets -- see uct_cxi_iface_open_rdzv_pte's comment on why this
     * isn't a self-chosen value. */
    cxi_build_dfa(sender_nid, sender_pid, md->pid_bits,
                 md->cxi_dev->info.rdzv_get_idx, &dfa, &idx_ext);

    /* Always fetches the full [0, rlength) range, never skipping past
     * mlength: unlike libfabric, any eager-attached bytes here are UCP's
     * unexpected-rndv header, not payload (see uct_ep_tag_rndv_zcopy's
     * warm/slim design), so they must always be overwritten. A no-op for
     * the common "slim" case (mlength always 0). */
    local_addr  = event->tgt_long.start;
    /* Clamp to the posted buffer's own capacity, not just rlength -- a
     * truncated receive must never DMA-write past its own posted buffer.
     * Mirrors libfabric's issue_rdzv_get(): data_len = MIN(ulen, rlength). */
    data_len    = ucs_min(posted_len, event->tgt_long.rlength);
    request_len = data_len;

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_GET;
        cmd.index_ext          = idx_ext;
        cmd.lac                = 0; /* LAC 0 only -- see design plan scoping */
        cmd.event_send_disable = 1;
        cmd.restricted         = 0;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = dfa;
        cmd.remote_offset      = event->tgt_long.remote_offset;
        cmd.local_addr         = local_addr;
        cmd.request_len        = request_len;
        cmd.match_bits         = event->tgt_long.rendezvous_id; /* the
                                   sender's own op id -- see this
                                   function's doc comment */
        cmd.user_ptr           = (uint64_t)(uintptr_t)rop;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(rop);
        ucs_error("cxi TAG rdzv Get emit failed: %d slot=%u", ret, slot);
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tx.cmdq);
    ucs_debug("cxi TAG [RDZV-GET-SW] slot=%u remote_offset=0x%lx "
             "local_addr=0x%lx len=%u", slot,
             (unsigned long)event->tgt_long.remote_offset,
             (unsigned long)local_addr, request_len);
    return UCS_OK;
}

/*
 * uct_cxi_iface_issue_rdzv_hdr_get -- corrective Get for a "warm" arrival
 * (mlength>0) whose pull was NIC-auto-issued (get_issued==1), which already
 * fetched [mlength, rlength) before software saw this event -- that can't
 * be undone, so this issues a second, small Get for [0, mlength) to
 * overwrite the eager-attached header bytes with the real payload. Same
 * DFA/PTE targeting as uct_cxi_iface_issue_rdzv_get() above; completion
 * feeds UCT_CXI_RNDV_SEEN_HDR_GET instead of SEEN_REPLY.
 */
static ucs_status_t
uct_cxi_iface_issue_rdzv_hdr_get(uct_cxi_iface_t *iface,
                                 const union c_event *event, uint16_t slot)
{
    uct_cxi_md_t              *md = uct_cxi_iface_md(iface);
    uint32_t                   init_dfa;
    uint32_t                   sender_nid;
    uint32_t                   sender_pid;
    union c_fab_addr           dfa;
    uint8_t                    idx_ext;
    uct_cxi_rdzv_hdr_get_op_t *rop;
    int                        ret;

    rop = (uct_cxi_rdzv_hdr_get_op_t *)ucs_mpool_get(
            &iface->tag.rdzv_get_op_pool);
    if (ucs_unlikely(rop == NULL)) {
        ucs_error("cxi TAG rdzv_get_op_pool exhausted (hdr get), slot=%u",
                 slot);
        return UCS_ERR_NO_RESOURCE;
    }
    rop->op.ep      = NULL;
    rop->op.comp    = NULL;
    rop->op.handler = uct_cxi_rdzv_hdr_get_comp;
    rop->iface      = iface;
    rop->slot       = slot;

    init_dfa   = event->tgt_long.initiator.initiator.process;
    sender_nid = cxi_dfa_nid(init_dfa);
    sender_pid = cxi_dfa_pid(init_dfa, md->pid_bits);
    cxi_build_dfa(sender_nid, sender_pid, md->pid_bits,
                 md->cxi_dev->info.rdzv_get_idx, &dfa, &idx_ext);

    {
        struct c_full_dma_cmd cmd = {};
        cmd.command.opcode     = C_CMD_GET;
        cmd.index_ext          = idx_ext;
        cmd.lac                = 0;
        cmd.event_send_disable = 1;
        cmd.restricted         = 0;
        cmd.eq                 = iface->evtq->eqn;
        cmd.dfa                = dfa;
        cmd.remote_offset      = event->tgt_long.remote_offset;
        cmd.local_addr         = event->tgt_long.start;
        cmd.request_len        = event->tgt_long.mlength;
        cmd.match_bits         = event->tgt_long.rendezvous_id;
        cmd.user_ptr           = (uint64_t)(uintptr_t)rop;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(rop);
        ucs_error("cxi TAG rdzv hdr Get emit failed: %d slot=%u", ret, slot);
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tx.cmdq);
    ucs_debug("cxi TAG [RDZV-HDR-GET-SW] slot=%u len=%u", slot,
             (unsigned)event->tgt_long.mlength);
    return UCS_OK;
}

/*
 * uct_cxi_iface_tag_match_lookup -- shared prefix for every tag-PTE match
 * handler (eager, rendezvous): the slot/ctx lookup is identical regardless
 * of which kind of match this turns out to be, so it lives here once
 * rather than in each handler. Classifying eager-vs-rendezvous
 * (event->tgt_long.rendezvous) and dispatching to the right handler is the
 * caller's job -- iface_progress() in cxi_iface.c -- not this function's
 * or the handlers' own; see the handlers' doc comments. A
 * SEARCH_AND_DELETE confirmation (buffer_id==UCT_CXI_TAG_SEARCH_DELETE_
 * SENTINEL) never reaches here at all -- iface_progress() routes it to
 * uct_cxi_iface_tag_handle_search_delete_confirm_eager() before either match
 * handler, let alone this shared lookup, is ever called.
 *
 * Returns NULL (nothing further to do) for a stale/already-resolved slot;
 * otherwise returns the matched ctx with *slot_p set.
 */
static uct_tag_context_t *
uct_cxi_iface_tag_match_lookup(uct_cxi_iface_t *iface,
                               const union c_event *event, int *slot_p)
{
    int slot = (int)event->tgt_long.buffer_id;

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale/racing event for an already-resolved slot -- e.g. UCP
         * force-cancelled this receive via the SW-matched path after the
         * hardware's own search-on-append raced our SEARCH_AND_DELETE.
         * Safe to drop; see file header. */
        ucs_debug("cxi TAG [MATCH-STALE] slot=%d already resolved, "
                 "dropping", slot);
        return NULL;
    }

    *slot_p = slot;
    return iface->tag.ctx[slot];
}

/*
 * uct_cxi_iface_tag_handle_eager_match -- a plain eager match, either
 * direct (C_EVENT_PUT, ptl_list==PRIORITY) or via delayed correlation
 * (C_EVENT_PUT_OVERFLOW). Never called for a rendezvous-flagged event --
 * see iface_progress()'s own dispatch.
 *
 * A direct match is the true zero-copy case: the priority LE was already
 * posted before the Put arrived, so hardware's own DMA already placed the
 * data in the caller's registered buffer -- inline_data stays NULL,
 * nothing more to move. A delayed match (C_EVENT_PUT_OVERFLOW) is NOT the
 * same: this data physically landed in the overflow ring before this
 * priority LE ever existed, and Portals4 never retroactively re-targets
 * an already-placed Put's DMA into a later-posted LE -- confirmed on real
 * hardware (test_cxi_tag.delayed_match_data_copy, every byte came back as
 * the pre-fill sentinel before this fix) and via libfabric's own
 * cxip_ux_send() (cxip_msg_hpc.c:593-640), which does the identical
 * explicit memcpy. So an explicit software copy from the overflow buffer
 * into priv->recv_addr is required here, unconditionally, whenever this
 * event type fires -- this is what "unified overflow-buffer lifecycle"
 * means: uct_cxi_iface_tag_handle_search_delete_confirm_eager() below does the
 * exact same copy, just into an eager_cb scratch buffer instead of a
 * posted receive's own buffer, for the case where no receive was posted
 * at all.
 *
 * Never called for a SEARCH_AND_DELETE confirmation (buffer_id in the
 * reserved SEARCH_AND_DELETE range, see UCT_CXI_TAG_SEARCH_DELETE_
 * BUFIDX_BASE in cxi_tag.h) either -- that shares this event type and
 * dispatch path but has no uct_tag_context_t behind it at all, so
 * iface_progress() routes it to uct_cxi_iface_tag_handle_search_delete_
 * confirm() directly, before ever choosing between this function and
 * tag_handle_rdzv_match().
 *
 * Does the copy for a delayed match, then releases the overflow-buffer
 * reference itself -- this handler is the only reader of this arrival's
 * overflow-buffer memory in this outcome (tag_handle_search_delete_
 * not_found() fires for the same arrival too, but never touches that
 * memory, so it must not be the thing reposting depends on -- see
 * uct_cxi_iface_tag_ovf_release()'s own doc comment).
 *
 * Checks iface->tag.cancel_ctx[slot].force before touching ctx/priv at
 * all -- see cancel_ctx's own doc comment in cxi_iface.h. Per the UCT
 * contract (uct.h), force=1 means UCP already treated the cancel as
 * successful the instant it called tag_recv_cancel(), and may have
 * recycled the ucp_request_t ctx/priv live in for a completely different
 * receive by the time this event arrives -- confirmed on real hardware
 * (a cxi_tag.c:1511 assertion firing with a *different*, live receive's
 * own priv->slot value). If the flag is set, the slot is reclaimed (the
 * LE is consumed either way) without ever reading ctx, and no callback or
 * copy happens (the copy would only ever be read by the callback anyway) --
 * but a still-held overflow-buffer reference (a warm PUT_OVERFLOW) is
 * released regardless, since the normal path below that would otherwise do
 * it never runs on this branch.
 */
void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    int                      slot;
    uct_tag_context_t      *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t                 stag;
    uint64_t                 imm;
    uint32_t                 mlength;
    ucs_status_t             status;
    int                      buf_idx;

    ctx = uct_cxi_iface_tag_match_lookup(iface, event, &slot);
    if (ctx == NULL) {
        return;
    }

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        iface->tag.cancel_ctx[slot].force = 0;
        if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
            (event->tgt_long.mlength > 0)) {
            /* Force-cancelled: the normal path below (which would
             * otherwise do this release after its copy) never runs, but
             * the reference taken at arrival still needs releasing or this
             * buffer generation can never repost. No copy needed -- ctx is
             * never read on this branch. */
            buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start);
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        ucs_debug("cxi TAG [MATCH-RACED-CANCEL] slot=%d -- force-cancelled, "
                 "dropping match silently", slot);
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;

    ucs_info("cxi EAGER TAG [%s] slot=%d tag=0x%lx mlength=%u",
             (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) ?
                     "OVF-MATCHED" : "DIRECT-MATCH",
             slot, (unsigned long)event->tgt_long.match_bits,
             (unsigned)event->tgt_long.mlength);

    if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
        (event->tgt_long.mlength > 0)) {
        /* Delayed match: copy out of the overflow buffer, then release --
         * see this function's own doc comment and uct_cxi_iface_tag_ovf_
         * release()'s. Gated on mlength>0 like the arrival side's own
         * increment (cxi_iface.h's ovf_refcnt doc comment): an mlength==0
         * delayed match never took a reference to begin with. */
        void *data;

        buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface, event->tgt_long.start);
        data    = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                             event->tgt_long.start);
        memcpy((void *)(uintptr_t)priv->recv_addr, data,
              event->tgt_long.mlength);
        uct_cxi_iface_tag_ovf_release(iface, buf_idx);
    }

    stag    = event->tgt_long.match_bits;
    imm     = event->tgt_long.header_data;
    mlength = event->tgt_long.mlength;
    status  = (event->tgt_long.rlength > mlength) ? UCS_ERR_MESSAGE_TRUNCATED :
                                                    UCS_OK;

    ctx->tag_consumed_cb(ctx);
    ctx->completed_cb(ctx, stag, imm, mlength, NULL, status);
}

/*
 * uct_cxi_iface_tag_rdzv_cancel_seen -- OR seen_bit into a force-cancelled
 * slot's accumulated cancel_ctx state and reclaim it once
 * UCT_CXI_RNDV_SEEN_REQUIRED is satisfied. Shared by every place that
 * accumulates events for a slot after tag_recv_cancel(force=1) -- see
 * cancel_ctx's own doc comment in cxi_iface.h for why the slot can't be
 * reclaimed just because force was requested: other events for the same
 * transfer may still be in flight.
 */
static inline void
uct_cxi_iface_tag_rdzv_cancel_seen(uct_cxi_iface_t *iface, int slot,
                                   uint8_t seen_bit)
{
    uint8_t seen = (iface->tag.cancel_ctx[slot].rndv_seen |= seen_bit);

    if ((seen & UCT_CXI_RNDV_SEEN_REQUIRED) == UCT_CXI_RNDV_SEEN_REQUIRED) {
        iface->tag.ctx[slot] = NULL;
        iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;
        iface->tag.cancel_ctx[slot].force = 0;
    }
}

/*
 * uct_cxi_iface_tag_rdzv_fail -- fail a rendezvous receive right away and
 * hand its slot to cancel_ctx-driven deferred reclaim, exactly as if it had
 * been force-cancelled: other required events (an independent Get, or a
 * not-yet-arrived Put/Rendezvous) may still be in flight and must drain
 * before the slot can be reused. Used for both Get-issuance failures and
 * Get-completion failures.
 */
static void
uct_cxi_iface_tag_rdzv_fail(uct_cxi_iface_t *iface, uct_tag_context_t *ctx,
                            int slot, uint8_t seen_bit, ucs_status_t status)
{
    uct_cxi_tag_ctx_priv_t *priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;

    ctx->completed_cb(ctx, priv->stag, 0, 0, NULL, status);
    iface->tag.cancel_ctx[slot].rndv_seen = priv->rndv_flags;
    iface->tag.cancel_ctx[slot].force     = 1;
    uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
}

/*
 * uct_cxi_iface_tag_handle_rdzv_match -- a rendezvous match: either
 * C_EVENT_PUT/C_EVENT_PUT_OVERFLOW with event->tgt_long.rendezvous==1, or
 * C_EVENT_RENDEZVOUS itself (announces the pull -- see
 * uct_cxi_iface_issue_rdzv_get above for the get_issued==0 case). A
 * receive completes once all of UCT_CXI_RNDV_SEEN_REQUIRED has arrived --
 * Put/Put_Overflow and Rendezvous can arrive in either order (confirmed on
 * real hardware; matches libfabric's rdzv_recv_req_event()); Reply/HDR_GET
 * are only ever resolved once C_EVENT_RENDEZVOUS itself has been processed
 * (see that branch below), so they can't race it. HDR_GET is marked "seen"
 * without a real Get whenever one isn't needed -- see its own comment.
 * tag_consumed_cb fires on the first event regardless: it only signals
 * "don't also match this in software".
 *
 * Checks cancel_ctx[slot].force before touching ctx/priv -- see its doc
 * comment in cxi_iface.h. A force-cancelled slot keeps accumulating via
 * uct_cxi_iface_tag_rdzv_cancel_seen() instead of priv until reclaimed --
 * including, on that branch, releasing any overflow-buffer reference this
 * arrival holds (a warm PUT_OVERFLOW), since the normal path below that
 * would otherwise do it never runs.
 */
void uct_cxi_iface_tag_handle_rdzv_match(uct_cxi_iface_t *iface,
                                         const union c_event *event)
{
    int                     slot;
    uct_tag_context_t     *ctx = uct_cxi_iface_tag_match_lookup(iface, event,
                                                                &slot);
    uct_cxi_tag_ctx_priv_t *priv;
    uint8_t                 seen_bit;
    uint64_t                stag;
    uint32_t                length;
    ucs_status_t            status;

    if (ctx == NULL) {
        return;
    }

    seen_bit = (event->hdr.event_type == C_EVENT_RENDEZVOUS) ?
            UCT_CXI_RNDV_SEEN_RNDV : UCT_CXI_RNDV_SEEN_PUT;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
            /* The buffer is already gone (UCP's contract for force=1) --
             * never issue a new Get into it. The corrective header Get (if
             * one would otherwise have been needed) is always abandoned
             * here; the main pull's Reply is abandoned too when
             * get_issued==0 (no Get was ever issued for it at all), but
             * left pending when get_issued==1 -- hardware's own auto-Get
             * is already in flight regardless of cancellation and will
             * complete normally via uct_cxi_iface_tag_handle_rdzv_reply(),
             * which routes back through this same force-cancel
             * accumulation. */
            ucs_debug("cxi TAG [RNDV-CANCEL] slot=%d get_issued=%u", slot,
                     (unsigned)event->tgt_long.get_issued);
            iface->tag.cancel_ctx[slot].rndv_seen |= UCT_CXI_RNDV_SEEN_HDR_GET;
            if (!event->tgt_long.get_issued) {
                iface->tag.cancel_ctx[slot].rndv_seen |= UCT_CXI_RNDV_SEEN_REPLY;
            }
        } else if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
                  (event->tgt_long.mlength > 0)) {
            /* Force-cancelled: the normal path below (which would
             * otherwise release this after caching the header) never runs,
             * but the reference taken at arrival still needs releasing or
             * this buffer generation can never repost. No copy needed --
             * priv is never read on this branch. */
            int buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                        event->tgt_long.start);
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);

    if (priv->rndv_flags == 0) {
        /* First of the three events seen for this slot -- fire
         * tag_consumed_cb immediately: it only concerns software
         * double-matching, not pull completion. */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_IS_RNDV;
        ctx->tag_consumed_cb(ctx);
    }

    if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
        ucs_debug("cxi TAG [RENDEZVOUS] slot=%d tag=0x%lx mlength=%u "
                 "rlength=%u get_issued=%u remote_offset=0x%lx",
                 slot, (unsigned long)event->tgt_long.match_bits,
                 (unsigned)event->tgt_long.mlength,
                 (unsigned)event->tgt_long.rlength,
                 (unsigned)event->tgt_long.get_issued,
                 (unsigned long)event->tgt_long.remote_offset);
    } else {
        ucs_debug("cxi TAG [%s-RNDV] slot=%d tag=0x%lx mlength=%u rlength=%u",
                 (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) ?
                         "OVF-MATCHED" : "DIRECT-MATCH",
                 slot, (unsigned long)event->tgt_long.match_bits,
                 (unsigned)event->tgt_long.mlength,
                 (unsigned)event->tgt_long.rlength);
        /* match_bits is only the real tag on C_EVENT_PUT/PUT_OVERFLOW.
        * C_EVENT_RENDEZVOUS's own match_bits is hardware-internal rendezvous
        * bookkeeping instead (confirmed on real hardware: masking to the low
        * 8 bits recovers the sender's own rdzv op id, exactly like the
        * source-side C_EVENT_GET's match_bits does -- see
        * uct_cxi_iface_tag_handle_rdzv_get's doc comment) -- capturing it here
        * would silently corrupt the tag reported to completed_cb whenever
        * C_EVENT_RENDEZVOUS happens to be processed after the Put-side event
        * (order is not guaranteed; only luck of ordering made every prior
        * test pass). */
        priv->stag = event->tgt_long.match_bits;
    }
    priv->length      = event->tgt_long.rlength;
    priv->rndv_flags |= seen_bit;
    if (event->tgt_long.rlength > priv->posted_len) {
        /* Real truncation is against the posted buffer's own capacity --
         * for a "slim" arrival (the common case) mlength is 0, so
         * "rlength > mlength" would be true for nearly every non-empty
         * message, truncated or not. See posted_len's own comment in
         * cxi_tag.h. */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_TRUNCATED;
    }

    if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
        if (ucs_unlikely(!event->tgt_long.get_issued)) {
            status = uct_cxi_iface_issue_rdzv_get(iface, event, (uint16_t)slot,
                                                priv->posted_len);
            if (ucs_unlikely(status != UCS_OK)) {
                /* Resource exhaustion issuing the pull -- fail now (no Get
                * means no Reply will ever arrive) and defer slot reclaim,
                * since the Put/Put_Overflow event may still be pending.
                * There is no separate corrective Get for get_issued==0
                * either way (the single pull always covers the full
                * range), so abandon both. */
                ucs_error("cxi TAG failed to issue rdzv Get, slot=%d", slot);
                uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot,
                        UCT_CXI_RNDV_SEEN_REPLY | UCT_CXI_RNDV_SEEN_HDR_GET,
                        status);
                return;
            }
            /* The single full-range pull already covers [0, rlength) --
             * there is no separate corrective Get for get_issued==0. */
            priv->rndv_flags |= UCT_CXI_RNDV_SEEN_HDR_GET;
        } else if (ucs_unlikely(event->tgt_long.mlength > 0)) {
            /* get_issued==1, warm: the NIC's own auto-issued pull already
             * skipped [0, mlength) -- fetch it explicitly. SEEN_HDR_GET is
             * left unset here; uct_cxi_rdzv_hdr_get_comp() sets it once
             * this Get actually completes. */
            status = uct_cxi_iface_issue_rdzv_hdr_get(iface, event,
                                                      (uint16_t)slot);
            if (ucs_unlikely(status != UCS_OK)) {
                ucs_error("cxi TAG failed to issue rdzv hdr Get, slot=%d",
                         slot);
                uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot,
                                           UCT_CXI_RNDV_SEEN_HDR_GET, status);
                return;
            }
        } else {
            /* get_issued==1, slim: nothing to correct. */
            priv->rndv_flags |= UCT_CXI_RNDV_SEEN_HDR_GET;
        }
    } else if (ucs_unlikely(event->tgt_long.mlength > 0)) {
        /* Warm Put/Put_Overflow: cache the real header for this peer (see
         * uct_ep_tag_rndv_zcopy's warm/slim design). Whether a corrective
         * Get will actually be needed depends on get_issued too, which only
         * C_EVENT_RENDEZVOUS carries -- that decision is made below, in the
         * C_EVENT_RENDEZVOUS branch, regardless of arrival order.
         *
         * PUT_OVERFLOW here also releases the overflow-buffer reference
         * this arrival took (mlength>0, so tag_handle_ovf_arrival() did
         * take one) after reading hdr_src -- this handler, not
         * tag_handle_search_delete_not_found(), is the actual reader of
         * that memory when a real priority LE wins the race. See
         * uct_cxi_iface_tag_ovf_release()'s and tag_handle_eager_match()'s
         * doc comments for the same rule and the bug this fixes
         * (forced_race_search_delete_vs_priority_append). */
        uint32_t initiator = event->tgt_long.initiator.initiator.process;
        const void *hdr_src;
        uct_cxi_rndv_hdr_wire_t hdr;
        khiter_t k;
        int ret;
        int buf_idx = -1;

        if (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) {
            buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start);
            hdr_src = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                 event->tgt_long.start);
        } else {
            hdr_src = (const void *)(uintptr_t)priv->recv_addr;
        }

        memcpy(&hdr, hdr_src, ucs_min(event->tgt_long.mlength, sizeof(hdr)));

        if (buf_idx >= 0) {
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }

        k = kh_put(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache,
                  initiator, &ret);
        if (ucs_likely(ret != UCS_KH_PUT_FAILED)) {
            kh_value(&iface->tag.rndv_peer_cache, k) =
                    (uct_cxi_rndv_peer_hdr_t){hdr.ep_id, hdr.md_index};
        }
    }

    if ((priv->rndv_flags & UCT_CXI_RNDV_SEEN_REQUIRED) !=
        UCT_CXI_RNDV_SEEN_REQUIRED) {
        return; /* Still waiting for another required event. */
    }

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    stag   = priv->stag;
    /* Delivered length is capped at the posted buffer's own capacity on
     * truncation, matching the eager path's contract (see the "truncation"
     * gtest). priv->length otherwise (non-truncated) never exceeds
     * posted_len, so this min is a no-op in that case. */
    length = ucs_min(priv->length, priv->posted_len);
    /* A failed Get completes immediately via uct_cxi_iface_tag_rdzv_fail()
     * instead of reaching here, so only truncation is left to check. */
    status = (priv->rndv_flags & UCT_CXI_RNDV_FLAG_TRUNCATED) ?
            UCS_ERR_MESSAGE_TRUNCATED : UCS_OK;

    /* imm is always 0 for rendezvous per uct_ep_tag_rndv_zcopy's own doc.
     * inline_data is always NULL, same reason as the eager handler. */
    ctx->completed_cb(ctx, stag, 0, length, NULL, status);
}

/*
 * uct_cxi_iface_tag_rdzv_reply_done -- completion for one of a rendezvous
 * receive's (up to two) Gets: the main pull's Reply (seen_bit=SEEN_REPLY,
 * via uct_cxi_iface_tag_handle_rdzv_reply or uct_cxi_rdzv_get_comp) or the
 * corrective header Get (seen_bit=SEEN_HDR_GET, via
 * uct_cxi_rdzv_hdr_get_comp). Marks seen_bit and fires completed_cb once
 * UCT_CXI_RNDV_SEEN_REQUIRED is satisfied.
 */
static void
uct_cxi_iface_tag_rdzv_reply_done(uct_cxi_iface_t *iface, int slot,
                                  uint8_t seen_bit, ucs_status_t get_status)
{
    uct_tag_context_t     *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t                stag;
    uint32_t                length;
    ucs_status_t            status;

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale/racing event for an already-resolved slot -- same
         * disposition as tag_handle_match's own bounds check. */
        ucs_debug("cxi TAG [RDZV-REPLY-STALE] slot=%d already resolved, "
                 "dropping", slot);
        return;
    }

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
        return;
    }

    ctx  = iface->tag.ctx[slot];
    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);
    ucs_assertv(priv->rndv_flags & UCT_CXI_RNDV_FLAG_IS_RNDV,
               "slot=%d rndv_flags=0x%x", slot, priv->rndv_flags);

    if (ucs_unlikely(get_status != UCS_OK)) {
        /* Fail now rather than accumulate -- there's no partial-success
         * notion for a failed pull, and this reports the real status
         * exactly once instead of trying to merge it with a second,
         * independent Get that might still be outstanding. */
        uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot, seen_bit, get_status);
        return;
    }

    priv->rndv_flags |= seen_bit;
    if ((priv->rndv_flags & UCT_CXI_RNDV_SEEN_REQUIRED) !=
        UCT_CXI_RNDV_SEEN_REQUIRED) {
        return; /* Still waiting for another required event. */
    }

    stag   = priv->stag;
    length = ucs_min(priv->length, priv->posted_len);
    status = (priv->rndv_flags & UCT_CXI_RNDV_FLAG_TRUNCATED) ?
            UCS_ERR_MESSAGE_TRUNCATED : UCS_OK;

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    ctx->completed_cb(ctx, stag, 0, length, NULL, status);
}

/*
 * uct_cxi_iface_tag_handle_rdzv_reply -- C_EVENT_REPLY with
 * event->init_short.rendezvous==1: a NIC-auto-issued (get_issued==1)
 * rendezvous Get completed. Its user_ptr is not a pointer -- it's a
 * struct cxi_rdzv_user_ptr bit-packed value (cxi_prov_hw.h:490-501) whose
 * buffer_id sub-field is the same priority-LE slot tag_handle_match()
 * itself dispatches on ("Buffer ID of the target LE from the Rendezvous
 * Put" per that struct's own doc comment) -- no separate sender-identity+
 * rendezvous_id lookup table needed. Called from cxi_iface.c's
 * iface_progress() *before* its normal C_EVENT_REPLY/user_ptr-as-pointer
 * handling, since that unconditional cast would otherwise misinterpret
 * this bit-packed value as a garbage uct_cxi_send_op_t pointer.
 */
void uct_cxi_iface_tag_handle_rdzv_reply(uct_cxi_iface_t *iface,
                                         const union c_event *event)
{
    struct cxi_rdzv_user_ptr *user_ptr =
            (struct cxi_rdzv_user_ptr *)&event->init_short.user_ptr;
    ucs_status_t status = uct_cxi_rc_to_status(cxi_event_rc(event));

    ucs_debug("cxi TAG [RDZV-GET-NIC] slot=%u rc=%d", user_ptr->buffer_id,
             cxi_event_rc(event));
    uct_cxi_iface_tag_rdzv_reply_done(iface, (int)user_ptr->buffer_id,
                                      UCT_CXI_RNDV_SEEN_REPLY, status);
}

/*
 * uct_cxi_rdzv_get_comp -- uct_cxi_send_op_t::handler for a software-issued
 * (get_issued==0) rendezvous Get's ordinary C_EVENT_REPLY (dispatched
 * through cxi_iface.c's existing, unmodified user_ptr-as-pointer path,
 * since we constructed this command's user_ptr ourselves -- see
 * uct_cxi_iface_issue_rdzv_get above).
 */
void uct_cxi_rdzv_get_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_rdzv_get_op_t *rop   = (uct_cxi_rdzv_get_op_t *)op;
    uct_cxi_iface_t        *iface = rop->iface;
    int                     slot  = rop->slot;

    ucs_mpool_put(rop);
    uct_cxi_iface_tag_rdzv_reply_done(iface, slot, UCT_CXI_RNDV_SEEN_REPLY,
                                      status);
}

/*
 * uct_cxi_rdzv_hdr_get_comp -- uct_cxi_send_op_t::handler for the
 * corrective header Get issued by uct_cxi_iface_issue_rdzv_hdr_get() for a
 * warm+matched, get_issued==1 rendezvous receive. Feeds UCT_CXI_RNDV_SEEN_
 * HDR_GET rather than UCT_CXI_RNDV_SEEN_REPLY -- see UCT_CXI_RNDV_SEEN_
 * HDR_GET's own comment in cxi_tag.h.
 */
void uct_cxi_rdzv_hdr_get_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_rdzv_hdr_get_op_t *rop   = (uct_cxi_rdzv_hdr_get_op_t *)op;
    uct_cxi_iface_t           *iface = rop->iface;
    int                        slot  = rop->slot;

    ucs_mpool_put(rop);
    uct_cxi_iface_tag_rdzv_reply_done(iface, slot, UCT_CXI_RNDV_SEEN_HDR_GET,
                                      status);
}

/*
 * uct_cxi_iface_tag_handle_unlink -- C_EVENT_UNLINK on the tag PTE.
 *
 * The priority-LE APPEND sets event_unlink_disable=1 (matches libfabric's
 * own _cxip_recv_req()), so the automatic use_once-on-match unlink never
 * generates an event at all -- tag_handle_match() already owns complete
 * slot cleanup for that case on its own. That leaves exactly two sources
 * for this handler, both from explicit commands:
 *   - A raced tag_recv_cancel() UNLINK that lost to a winning match
 *     (return_code==C_RC_ENTRY_NOT_FOUND) -- self-identifying, drop.
 *   - Manual unlink of an overflow-ring buffer at teardown
 *     (ptl_list==OVERFLOW) -- nothing to repost mid-run.
 *   - A genuine tag_recv_cancel() confirmation (ptl_list==PRIORITY,
 *     return_code==C_RC_OK) -- the real case this handler exists for, and
 *     now unambiguous: every priority-list C_EVENT_UNLINK that reaches
 *     here is a real explicit-cancel confirmation.
 *
 * This event winning outright (as opposed to C_RC_ENTRY_NOT_FOUND above)
 * means the LE was removed before any match ever happened -- a complete,
 * terminal disposition regardless of whether the receive would have been
 * eager or rendezvous, so a force-cancelled slot reaching here is always
 * reclaimed immediately, with no rndv_seen accumulation needed (contrast
 * tag_handle_rdzv_match()/tag_rdzv_reply_done(), which handle the case
 * where a match happened first instead). Checks iface->tag.
 * cancel_ctx[slot].force before touching ctx/priv at all -- see
 * cancel_ctx's own doc comment in cxi_iface.h.
 */
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    int                     slot;
    uct_tag_context_t      *ctx;
    uct_cxi_tag_ctx_priv_t *priv;

    ucs_debug("cxi TAG [UNLINK] buf_id=%d ptl_list=%d rc=%d",
             (int)event->tgt_long.buffer_id,
             (int)event->tgt_long.ptl_list, cxi_event_rc(event));

    if (cxi_event_rc(event) == C_RC_ENTRY_NOT_FOUND) {
        ucs_debug("cxi TAG [UNLINK-RACED] buf_id=%d -- lost to a winning "
                 "match, dropping", (int)event->tgt_long.buffer_id);
        return;
    }

    if (event->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) {
        ucs_debug("cxi TAG overflow LE C_EVENT_UNLINK buf=%d (manual)",
                 (int)event->tgt_long.buffer_id);
        return;
    }

    slot = (int)event->tgt_long.buffer_id;
    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        return;
    }

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        iface->tag.ctx[slot] = NULL;
        iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;
        iface->tag.cancel_ctx[slot].force = 0;
        return;
    }

    ctx  = iface->tag.ctx[slot];
    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    ctx->completed_cb(ctx, 0, 0, 0, NULL, UCS_ERR_CANCELED);
}


/* -------------------------------------------------------------------------
 * Sender-side ops -- direct analogues of cxi_am.c's short/bcopy/zcopy
 * -------------------------------------------------------------------------
 */

static void uct_cxi_tag_bcopy_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    ucs_mpool_put((uct_cxi_send_desc_t *)op);
}

/*
 * uct_cxi_ep_tag_eager_short -- unrestricted IDC tag send (<= 192 B
 * payload). No 8-byte header reservation needed (unlike AM) -- imm always
 * travels out-of-band via header_data, and eager_short has no imm
 * parameter at all (implicitly 0 per the API; use bcopy for nonzero imm).
 */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
    uct_cxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_tag_ep_iface(ep);
    int              ret;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_UNR, "tag_eager_short");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_cstate_cmd cstate   = {};
        cstate.event_send_disable    = 1;
        cstate.restricted            = 0; /* unrestricted -> TAG PTE */
        cstate.index_ext             = ep->dfa_tag_idx_ext;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi ep %p tag_eager_short cstate emit failed: %d",
                 ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa        = ep->dfa_tag;
        hdr.match_bits = tag;

        ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &hdr, data, length);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_error("cxi ep %p tag_eager_short idc_msg emit failed: %d",
                 ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ucs_debug("cxi TAG [SEND-SHORT] ep=%p tag=0x%lx len=%zu", ep,
             (unsigned long)tag, length);
    return UCS_OK;
}

/*
 * uct_cxi_ep_tag_eager_bcopy -- unrestricted DMA tag send via bounce
 * buffer (shared desc_pool, same as RMA/AM bcopy).
 */
ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                    uint64_t imm, uct_pack_callback_t pack_cb,
                                    void *arg, unsigned flags)
{
    uct_cxi_ep_t         *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface = uct_cxi_tag_ep_iface(ep);
    uct_cxi_send_desc_t  *desc;
    size_t                length;
    int                   ret;

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);

    desc->op.ep      = ep;
    desc->op.comp    = NULL;
    desc->op.handler = uct_cxi_tag_bcopy_comp;

    {
        struct c_full_dma_cmd cmd  = {};
        cmd.command.opcode         = C_CMD_PUT;
        cmd.index_ext              = ep->dfa_tag_idx_ext;
        cmd.lac                    = desc->lac;
        cmd.event_send_disable     = 1;
        cmd.event_success_disable  = 0;
        cmd.restricted             = 0;
        cmd.eq                     = iface->evtq->eqn;
        cmd.dfa                    = ep->dfa_tag;
        cmd.match_bits             = tag;
        cmd.header_data            = imm;
        cmd.remote_offset          = 0;
        cmd.local_addr             = desc->iova;
        cmd.request_len            = (uint32_t)length;
        cmd.user_ptr               = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        ucs_error("cxi ep %p tag_eager_bcopy emit failed: %d", ep, ret);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    ucs_debug("cxi TAG [SEND-BCOPY] ep=%p tag=0x%lx imm=0x%lx len=%zu", ep,
             (unsigned long)tag, (unsigned long)imm, length);
    return (ssize_t)length;
}

/*
 * uct_cxi_ep_tag_eager_zcopy -- unrestricted DMA tag send directly from
 * the caller's registered buffer.
 */
ucs_status_t uct_cxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_tag_ep_iface(ep);
    uct_cxi_mem_handle_t *memh   = (uct_cxi_mem_handle_t *)iov[0].memh;
    size_t                length = uct_iov_get_length(iov);
    uct_cxi_send_op_t    *op;
    int                   ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_eager_zcopy");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = comp;
    op->handler = NULL;

    {
        struct c_full_dma_cmd cmd  = {};
        cmd.command.opcode         = C_CMD_PUT;
        cmd.index_ext              = ep->dfa_tag_idx_ext;
        cmd.lac                    = memh->cxi_md->lac;
        cmd.event_send_disable     = 1;
        cmd.event_success_disable  = 0;
        cmd.restricted             = 0;
        cmd.eq                     = iface->evtq->eqn;
        cmd.dfa                    = ep->dfa_tag;
        cmd.match_bits             = tag;
        cmd.header_data            = imm;
        cmd.remote_offset          = 0;
        cmd.local_addr             = memh->iova_offset +
                                     (uint64_t)(uintptr_t)iov[0].buffer;
        cmd.request_len            = (uint32_t)length;
        cmd.user_ptr               = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        ucs_error("cxi ep %p tag_eager_zcopy emit failed: %d", ep, ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    ucs_debug("cxi TAG [SEND-ZCOPY] ep=%p tag=0x%lx imm=0x%lx len=%zu", ep,
             (unsigned long)tag, (unsigned long)imm, length);
    return UCS_INPROGRESS;
}


/* -------------------------------------------------------------------------
 * Rendezvous ops (Phase B, direct-match only -- see the design plan's
 * "Current increment")
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_rdzv_put_ack_comp -- uct_cxi_send_op_t::handler for a rendezvous
 * Put's own local C_EVENT_ACK. Confirmed on real hardware (a segfault,
 * root-caused via gdb -- the generic ACK dispatch in cxi_iface.c
 * unconditionally casts user_ptr to uct_cxi_send_op_t*, and this op wasn't
 * actually one) and against libfabric's own cxip_send_rdzv_put_cb()
 * (cxip_msg_hpc.c:4347-4390): this event genuinely fires despite
 * event_send_disable=1 -- not a flag we're missing, hardware just doesn't
 * honor it for this opcode.
 *
 * On success this is *not* the real completion signal for
 * uct_ep_tag_rndv_zcopy's own comp -- that only fires later, once the
 * peer's Get actually lands (uct_cxi_iface_tag_handle_rdzv_get), confirmed
 * via cxi_prov_hw.h's own cxi_event_rc() classification: C_EVENT_GET is a
 * *target* event (fires on us, the side whose exposure LE was read) and
 * C_EVENT_REPLY is an *initiator* event (fires on the peer that issued the
 * Get) -- both sides of that pull already correctly propagate a failed
 * cxi_event_rc() through to completed_cb, independent of this ACK. So on
 * success this handler must never free the op or touch comp -- it stays
 * alive in iface->rdzv.ops[], waiting for that Get.
 *
 * On failure, though, the Put itself never landed -- nothing on the target
 * was ever exposed to a Rendezvous match, so no Get will ever be issued
 * and no C_EVENT_GET will ever arrive to complete this op through the
 * normal path. This is the ACK's entire reason for existing (matches
 * libfabric's own rdzv_send_req_complete() on a bad ACK,
 * cxip_msg_hpc.c:4386-4389) -- without handling it here, a dropped/failed
 * rendezvous Put would leave rop's id permanently allocated, hanging the
 * caller's completion.
 */
void uct_cxi_rdzv_put_ack_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_rdzv_op_t *rop   = (uct_cxi_rdzv_op_t *)op;
    uct_cxi_iface_t   *iface = uct_cxi_tag_ep_iface(rop->op.ep);

    if (ucs_likely(status == UCS_OK)) {
        return;
    }

    ucs_error("cxi TAG rndv Put ACK failed: %s", ucs_status_string(status));
    rop->valid = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = rop->id;
    if (rop->comp != NULL) {
        uct_invoke_completion(rop->comp, status);
    }
}

/*
 * uct_cxi_ep_tag_rndv_zcopy -- expose iov for a native hardware pull.
 *
 * Targets ep->dfa_tag, the same PTE eager uses (C_CMD_RENDEZVOUS_PUT is a
 * distinct opcode but lands on the same matching PTE). remote_offset is
 * the iov's own address, mirroring libfabric's local_addr==remote_offset
 * pattern, so the receiver's later Get (software- or NIC-issued) can
 * address straight into it against the dedicated, matching (not
 * restricted) rendezvous PTE -- see uct_cxi_rdzv_op_t's doc comment.
 * cmd.rendezvous_id carries this op's own iface->rdzv.ops[] index to the
 * receiver via its RENDEZVOUS event, which stamps it into its own Get's
 * match_bits for an O(1) lookup on our C_EVENT_GET instead of a scan.
 *
 * header/header_length -- see uct_cxi_ep_t::rndv_hdr_state (cxi_ep.h) for
 * the warm/slim design this implements: UNCONFIRMED sends the full header
 * inline (eager_length=header_length, rop->is_warm=1, corrected later if
 * matched -- see UCT_CXI_RNDV_SEEN_HDR_GET); CONFIRMED sends only the
 * volatile trailing 8 bytes via header_data (eager_length=0, the prior
 * always-0 behavior), letting the receiver reconstruct the rest from its
 * per-peer cache.
 *
 * Returns a uct_cxi_rdzv_op_t* (&iface->rdzv.ops[id]), tracked until the
 * peer's Get lands (uct_cxi_iface_tag_handle_rdzv_get) or
 * uct_ep_tag_rndv_cancel() removes it.
 */
ucs_status_ptr_t uct_cxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                           const void *header,
                                           unsigned header_length,
                                           const uct_iov_t *iov,
                                           size_t iovcnt, unsigned flags,
                                           uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_tag_ep_iface(ep);
    uct_cxi_mem_handle_t *memh   = (uct_cxi_mem_handle_t *)iov[0].memh;
    size_t                length = uct_iov_get_length(iov);
    uint64_t              local_addr;
    uint32_t              id;
    uct_cxi_rdzv_op_t    *rop;
    int                   is_warm;
    uint32_t              eager_length;
    uint64_t              header_data;
    int                   ret;

    if (ucs_unlikely(iovcnt != 1ul)) {
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    if (ucs_unlikely(iface->rdzv.free_count == 0)) {
        return UCS_STATUS_PTR(UCS_ERR_EXCEEDS_LIMIT);
    }
    id  = iface->rdzv.free_ids[--iface->rdzv.free_count];
    rop = &iface->rdzv.ops[id];

    is_warm = (ep->rndv_hdr_state == UCT_CXI_RNDV_HDR_UNCONFIRMED);
    if (ucs_unlikely(is_warm)) {
        eager_length = header_length;
        header_data  = 0; /* full header travels via the eager attach instead */
    } else {
        /* Only req_id varies per send (see uct_cxi_rndv_hdr_wire_t) --
         * header_length is always exactly sizeof(uct_cxi_rndv_hdr_wire_t)
         * whenever this offload protocol is in use (see UCT_CXI_TAG_RNDV_
         * MAX_HDR's comment), but guard anyway rather than read past the
         * caller's buffer. */
        eager_length = 0;
        ucs_assert(header_length >= sizeof(uct_cxi_rndv_hdr_wire_t));
        header_data = ((const uct_cxi_rndv_hdr_wire_t *)header)->req_id;
    }

    local_addr    = memh->iova_offset + (uint64_t)(uintptr_t)iov[0].buffer;
    rop->op.ep      = ep;   /* real ep -- unlike uct_cxi_rdzv_get_op_t, this
                             * op has a genuine owning ep, so the normal
                             * ep->outstanding/iface->tx.outstanding/flush
                             * bookkeeping in cxi_iface.c's generic ACK
                             * dispatch applies (matches the ep->outstanding++
                             * / iface->tx.outstanding++ below). */
    rop->op.comp    = NULL; /* unused -- rop's own `comp` below is the real
                             * completion, fired later once the peer's Get
                             * lands, not from this generic dispatch path */
    rop->op.handler = uct_cxi_rdzv_put_ack_comp;
    rop->comp     = comp;
    rop->length   = (uint32_t)length;
    rop->id       = (uint8_t)id;
    rop->valid    = 1;
    rop->is_warm  = (uint8_t)is_warm;

    {
        struct c_full_dma_cmd cmd  = {};
        cmd.command.opcode         = C_CMD_RENDEZVOUS_PUT;
        cmd.index_ext              = ep->dfa_tag_idx_ext;
        cmd.lac                    = memh->cxi_md->lac;
        cmd.event_send_disable     = 1;
        cmd.restricted             = 0;
        cmd.eq                     = iface->evtq->eqn;
        cmd.dfa                    = ep->dfa_tag;
        cmd.match_bits             = tag;
        cmd.local_addr              = local_addr;
        cmd.request_len             = (uint32_t)length;
        cmd.remote_offset           = local_addr;
        cmd.eager_length            = eager_length;
        cmd.header_data             = header_data;
        cmd.use_offset_for_get      = 1;
        cmd.rendezvous_id           = (uint8_t)id; /* carried to the
                                            receiver via its RENDEZVOUS
                                            event -- see this function's
                                            own doc comment */
        cmd.user_ptr                = (uint64_t)(uintptr_t)&rop->op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        rop->valid = 0;
        iface->rdzv.free_ids[iface->rdzv.free_count++] = id;
        ucs_error("cxi ep %p tag_rndv_zcopy emit failed: %d", ep, ret);
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    ucs_debug("cxi TAG [RNDV-SEND] ep=%p tag=0x%lx id=%u local_addr=0x%lx "
             "len=%zu warm=%d", ep, (unsigned long)tag, id,
             (unsigned long)local_addr, length, is_warm);
    return rop;
}

/*
 * uct_cxi_ep_tag_rndv_cancel -- bare software-tracking removal, no
 * hardware operation. See cxi_tag.h's uct_cxi_rdzv_op_t comment and the
 * design plan's "Current increment" section for why this can never race a
 * real Get: op is only ever removed here or by
 * uct_cxi_iface_tag_handle_rdzv_get, and UCP's own calling contract
 * guarantees this is never invoked on an already-completed op.
 */
ucs_status_t uct_cxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *op)
{
    uct_cxi_ep_t      *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t   *iface = uct_cxi_tag_ep_iface(ep);
    uct_cxi_rdzv_op_t *rop   = (uct_cxi_rdzv_op_t *)op;

    rop->valid = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = rop->id;
    return UCS_OK;
}

/*
 * uct_cxi_iface_tag_handle_rdzv_get -- C_EVENT_GET on iface->rdzv.pte: a
 * peer's Get read from our exposed catch-all LE. match_bits carries the
 * op's own id straight back to us (DEFAULT-protocol style -- see
 * uct_cxi_rdzv_op_t's own doc comment in cxi_tag.h for the full design and
 * why this works only because the PTE is matching, not restricted), giving
 * O(1) lookup into iface->rdzv.ops[] instead of a scan. Fires comp once
 * found -- the buffer is now safe to reuse, per uct_ep_tag_rndv_zcopy's
 * own doc.
 *
 * Only the low 8 bits of match_bits are ours -- confirmed on real hardware
 * (id values checked bit-for-bit against what was assigned) that Cassini's
 * own auto-issued Get construction places our id in exactly the bit range
 * libfabric's own union cxip_match_bits reserves for rdzv_id_lo
 * (CXIP_RDZV_ID_CMD_WIDTH=8 bits, cxip.h:592,650) -- bits above that carry
 * something else hardware-internal (observed: consistently forced high,
 * plausibly rdzv_lac or a protocol marker in the same union's other
 * bitfields), so the raw value must be masked, not used directly. This
 * also bounds UCT_CXI_RDZV_MAX_OUTSTANDING_MAX at 256 correctly -- see
 * cxi_tag.h.
 */
void uct_cxi_iface_tag_handle_rdzv_get(uct_cxi_iface_t *iface,
                                       const union c_event *event)
{
    uint32_t           id = (uint32_t)(event->tgt_long.match_bits & 0xFF);
    uct_cxi_rdzv_op_t *rop;
    ucs_status_t       status;

    if ((id >= iface->rdzv.max_outstanding) || !iface->rdzv.ops[id].valid) {
        ucs_debug("cxi TAG [RNDV-GOT-STALE] id=%u -- no matching outstanding "
                 "rndv_zcopy, already cancelled?", id);
        return;
    }

    rop        = &iface->rdzv.ops[id];
    rop->valid = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = id;
    status     = uct_cxi_rc_to_status(cxi_event_rc(event));
    ucs_debug("cxi TAG [RNDV-GOT] id=%u len=%u rc=%d", id, rop->length,
             cxi_event_rc(event));

    /* A warm Get landing proves the receiver processed (and cached) this
     * op's header -- see uct_cxi_rndv_hdr_state_t (cxi_ep.h). Only the
     * first such confirmation per ep matters. */
    if (ucs_unlikely(rop->is_warm)) {
        rop->op.ep->rndv_hdr_state = UCT_CXI_RNDV_HDR_CONFIRMED;
        ucs_debug("cxi TAG [RNDV-HDR-CONFIRMED] ep=%p id=%u", rop->op.ep, id);
    }

    if (rop->comp != NULL) {
        uct_invoke_completion(rop->comp, status);
    }
}

/*
 * uct_cxi_ep_tag_rndv_request -- stubbed for this increment, deliberately.
 * See the design plan's "Current increment" section: making this correct
 * requires receive-side rndv_cb dispatch (distinguishing a software-only
 * rendezvous request from a plain eager Put or a real zcopy-backed one),
 * which is out of scope here (direct-match/zcopy only). Confirmed safe to
 * defer: ucp_rndv_send_handle_status_from_pending() (rndv.c:1799-1818)
 * turns any non-OK/non-NO_RESOURCE status, including UCS_ERR_UNSUPPORTED,
 * into a clean error completion delivered to the app via
 * ucp_ep_req_purge() -- not a hang or corruption.
 */
ucs_status_t uct_cxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length,
                                         unsigned flags)
{
    return UCS_ERR_UNSUPPORTED;
}


/* -------------------------------------------------------------------------
 * Receiver-side ops (priority-LE posting, the hot path)
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx)
{
    uct_cxi_iface_t        *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_mem_handle_t   *memh;
    uct_cxi_tag_ctx_priv_t *priv;
    uint16_t                slot;
    struct c_target_cmd     le    = {};
    int                     ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_recv_zcopy");

    /* Exactly fills UCT_TAG_PRIV_LEN with recv_addr added -- catch it
     * here, not as a silent out-of-bounds write into
     * uct_tag_context_t::priv, if either grows again. */
    UCS_STATIC_ASSERT(sizeof(uct_cxi_tag_ctx_priv_t) <= UCT_TAG_PRIV_LEN);

    if (ucs_unlikely(iface->tag.free_count == 0)) {
        return UCS_ERR_EXCEEDS_LIMIT;
    }

    memh = (uct_cxi_mem_handle_t *)iov[0].memh;
    slot = iface->tag.free_list[--iface->tag.free_count];

    priv                    = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    priv->slot              = slot;
    priv->rndv_flags        = 0;
    priv->posted_len        = (uint32_t)iov[0].length;
    priv->recv_addr         = (uint64_t)(uintptr_t)iov[0].buffer;
    iface->tag.ctx[slot] = ctx;

    le.command.opcode        = C_CMD_TGT_APPEND;
    le.ptl_list              = C_PTL_LIST_PRIORITY;
    le.ptlte_index           = iface->tag.pte->ptn;
    le.op_put                = 1;
    le.op_get                = 0;
    le.use_once              = 1;
    le.manage_local          = 1; /* mandatory even for a single-message LE
                                   * -- makes Cassini ignore initiator
                                   * remote_offset (libfabric's own
                                   * _cxip_recv_req() comment) */
    le.unexpected_hdr_disable = 0; /* empirically confirmed to have no
                                     * effect on priority-list APPENDs
                                     * either way -- left at the real
                                     * default */
    le.unrestricted_body_ro  = 1;
    le.unrestricted_end_ro   = 1;
    le.event_link_disable    = 1; /* no append-ack needed */
    le.event_unlink_disable  = 1; /* Suppress the event for the automatic
                                   * (use_once-on-match) unlinkevent.
                                   * The separate, explicit C_CMD_TGT_UNLINK
                                   * issued by tag_recv_cancel() has its
                                   * own event_unlink_disable setting left
                                   * on. Thus, every C_EVENT_UNLINK on PTE
                                   * priority list is a cancel confirmation. */
    le.no_truncate           = 0; /* allow truncated delivery so
                                   * UCS_ERR_TRUNCATED can be reported,
                                   * unlike AM which rejects outright */
    le.restart_seq           = 0;
    le.match_id              = CXI_MATCH_ID_ANY;
    le.buffer_id             = slot;
    le.lac                   = memh->cxi_md->lac;
    le.start                 = memh->iova_offset +
                               (uint64_t)(uintptr_t)iov[0].buffer;
    le.length                = iov[0].length;
    le.ignore_bits           = ~tag_mask;
    le.match_bits            = tag;

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &le);
    if (ucs_unlikely(ret != 0)) {
        iface->tag.ctx[slot] = NULL;
        iface->tag.free_list[iface->tag.free_count++] = slot;
        ucs_error("cxi TAG priority LE APPEND slot %u: %d", slot, ret);
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tgt.cmdq);
    ucs_info("cxi TAG [PRI-LE-POST] slot=%u tag=0x%lx tag_mask=0x%lx",
             (unsigned)slot, tag, tag_mask);
    return UCS_OK;
}

ucs_status_t uct_cxi_iface_tag_recv_cancel(uct_iface_h tl_iface,
                                           uct_tag_context_t *ctx, int force)
{
    uct_cxi_iface_t        *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_tag_ctx_priv_t *priv  = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    struct c_target_cmd     cmd   = {};
    int                     ret;

    if (force) {
        /* priv is read here for the last time -- synchronously, while
         * ctx is still guaranteed to be OUR caller's own valid, in-flight
         * request (uct.h's own doc comment: force=1 means UCP "assumes
         * the cancel is... successful" the instant this call is made, so
         * it may recycle ctx/priv for a completely different receive any
         * time after this function returns). Snapshot whatever
         * rendezvous accumulation exists so far into iface-owned memory
         * -- see cancel_ctx's own doc comment in cxi_iface.h for why
         * neither ctx nor priv may be touched again for this slot from
         * here on, by this function or any event handler. */
        iface->tag.cancel_ctx[priv->slot].rndv_seen = priv->rndv_flags;
        iface->tag.cancel_ctx[priv->slot].force     = 1;
    }

    cmd.command.opcode = C_CMD_TGT_UNLINK;
    cmd.ptl_list       = C_PTL_LIST_PRIORITY;
    cmd.ptlte_index    = iface->tag.pte->ptn;
    cmd.buffer_id      = priv->slot;

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &cmd);
    if (ucs_unlikely(ret != 0)) {
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tgt.cmdq);
    return UCS_OK;
}
