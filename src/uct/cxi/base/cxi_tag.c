/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload -- Phase A (eager only).
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

    self->tag.max_outstanding = ucs_min(config->tag_max_outstanding,
                                        UCT_CXI_TAG_MAX_OUTSTANDING_MAX);
    self->tag.num_bufs        = config->tag_ovf_num_bufs;
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
            goto err_free_free_list;
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
err_unmap_rx:
    uct_cxi_do_unmap(&self->tag.rx_mh);
    ucs_free(self->tag.rx_base);
    self->tag.rx_base = NULL;
err_cleanup_unexp_pool:
    ucs_mpool_cleanup(&self->tag.unexp_pool, 1);
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

    ucs_mpool_cleanup(&self->tag.unexp_pool, 1);
    ucs_free(self->tag.free_list);
    ucs_free(self->tag.ctx);
}


/* -------------------------------------------------------------------------
 * Event dispatch (called from cxi_iface.c's iface_progress())
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_iface_tag_handle_ovf_arrival -- an unexpected message landed in
 * the overflow ring (C_EVENT_PUT, ptl_list==C_PTL_LIST_OVERFLOW). Copy out
 * immediately, tell Cassini we've consumed it (SEARCH_AND_DELETE), and
 * hand off to UCP's own SW tag-matching via eager_cb/rndv_cb -- no
 * tag_consumed_cb/completed_cb/rndv_cb on this path, those only exist on a
 * uct_tag_context_t from an already-posted tag_recv_zcopy, which by
 * definition doesn't exist for an unexpected message.
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    int                  buf_idx  = (int)event->tgt_long.buffer_id;
#if 1
    /* IN PROGRESS -- current, deliberate interim behavior, not a bug or a
     * leftover experiment: drop every unexpected arrival entirely (no
     * copy, no eager_cb/rndv_cb, no SEARCH_AND_DELETE), pending a decision
     * on whether unexpected messages should ever be handed off to UCP at
     * all vs. resolved entirely by the NIC (see the design plan's
     * "Part 2/3" discussion -- explicitly undecided, not a blocker for
     * the rendezvous work this increment is building). This trades away
     * UCP's software tag-matching fallback for unexpected messages in
     * exchange for zero risk of the Part-2 force-cancel race. The
     * previous, known-racy-but-functional implementation (copy out,
     * SEARCH_AND_DELETE, unconditional eager_cb) is kept below in #else
     * for easy revert once that decision is made -- do not delete it.
     * auto_unlinked repost stays unconditional since we never read the
     * data here, so there's no reuse-before-read race to guard against. */
    ucs_debug("cxi TAG [OVF-ARRIVAL-IGNORED] buf_idx=%d tag=0x%lx "
             "mlength=%u -- unexpected-message handling not yet decided, "
             "dropping", buf_idx, (unsigned long)event->tgt_long.match_bits,
             (unsigned)event->tgt_long.mlength);

    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        uct_cxi_iface_post_tag_ovf_le(iface, buf_idx, 1);
    }
    return;
#else
    uint8_t             *buf_va   = iface->tag.rx_base +
                                    (size_t)buf_idx * iface->tag.buf_size;
    uint64_t             buf_iova = iface->tag.rx_mh.iova_offset +
                                    (uint64_t)(uintptr_t)buf_va;
    uint32_t             len      = event->tgt_long.mlength;
    uint64_t             tag      = event->tgt_long.match_bits;
    uint64_t             imm      = event->tgt_long.header_data;
    void                *data     = buf_va +
                                    (size_t)(event->tgt_long.start - buf_iova);
    // struct c_target_cmd  sd       = {};
    void                *elem;
    void                *context  = NULL;
    // int                  ret;

    ucs_debug("cxi TAG [OVF-ARRIVAL] buf_idx=%d tag=0x%lx mlength=%u "
             "rlength=%u start=0x%lx auto_unlinked=%u",
             buf_idx, tag, len, (unsigned)event->tgt_long.rlength,
             (unsigned long)event->tgt_long.start,
             (unsigned)event->tgt_long.auto_unlinked);

    /* Zero-byte unexpected Puts can't happen for tag (no analogous
     * fabric-level probe traffic targets this PTE), but guard anyway. */
    elem = (len > 0) ? ucs_mpool_get(&iface->tag.unexp_pool) : NULL;
    if (ucs_unlikely((elem == NULL) && (len > 0))) {
        ucs_error("cxi TAG overflow: unexp_pool exhausted, dropping "
                 "unexpected message tag=0x%lx len=%u", tag, len);
    } else if (len > 0) {
        memcpy(elem, data, len);
    }

    // /* Tell Cassini we've consumed this -- clears the internal
    //  * unexpected-header record so a LATER-posted priority LE's automatic
    //  * search-on-append can never find and re-deliver it. Issued
    //  * unconditionally, even on unexp_pool exhaustion above, since leaving
    //  * a stale record around risks a future match reading memory we may
    //  * have already reused.
    //  *
    //  * Validated fix, kept for reference/revert (see design plan's "Part
    //  * 2 addendum"): targets C_PTL_LIST_UNEXPECTED, not OVERFLOW --
    //  * libfabric's own SEARCH/SEARCH_AND_DELETE call sites (cxip_msg_hpc.c,
    //  * cxip_msg.c) target this exclusively; OVERFLOW is just the
    //  * receive-buffer list, UNEXPECTED is the actual
    //  * search-on-append-visible tracking list. match_id must be
    //  * CXI_MATCH_ID_ANY, not zero-init, to be a real wildcard. buffer_id
    //  * is set to a sentinel distinguishable from any real priority-LE slot
    //  * (always < max_outstanding <= 65535) so tag_handle_match() can
    //  * recognize and skip this command's own found+deleted completion
    //  * event rather than treating it as a genuine delayed match. */
    // sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
    // sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    // sd.ptlte_index    = iface->tag.pte->ptn;
    // sd.match_bits     = tag;
    // sd.ignore_bits    = 0;
    // sd.match_id       = CXI_MATCH_ID_ANY;
    // sd.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_SENTINEL;
    // ret = cxi_cq_emit_target(iface->tgt.cmdq, &sd);
    // if (ucs_unlikely(ret != 0)) {
    //     ucs_warn("cxi TAG SEARCH_AND_DELETE emit failed: %d", ret);
    // } else {
    //     cxi_cq_ring(iface->tgt.cmdq);
    // }

    if ((elem != NULL) || (len == 0)) {
        /* No UCT_CB_PARAM_FLAG_DESC offered -- eager_cb must copy out
         * synchronously if it wants to keep the data, matching this same
         * transport's existing AM convention (uct_iface_invoke_am(...,
         * flags=0) below). We reclaim our own buffer right away
         * regardless of the returned status. */
        (void)iface->tag.eager_cb(iface->tag.eager_arg, elem, len,
                                  UCT_CB_PARAM_FLAG_FIRST, tag, imm,
                                  &context);
        if (elem != NULL) {
            ucs_mpool_put(elem);
        }
    }

    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        /* EQ delivery is ordered, so this Put is guaranteed to be the
         * last one for this buffer generation -- see file header. */
        uct_cxi_iface_post_tag_ovf_le(iface, buf_idx, 1);
    }
#endif
}

/*
 * uct_cxi_iface_tag_handle_match -- a priority-list LE was matched, either
 * directly (C_EVENT_PUT, ptl_list==PRIORITY) or via delayed correlation
 * (C_EVENT_PUT_OVERFLOW, the message had already landed in the overflow
 * ring before this LE was posted). Both carry identical fields for our
 * purposes and produce identical disposition.
 */
void uct_cxi_iface_tag_handle_match(uct_cxi_iface_t *iface,
                                    const union c_event *event)
{
    int                     slot = (int)event->tgt_long.buffer_id;
    uct_tag_context_t     *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t                stag;
    uint64_t                imm;
    uint32_t                mlength;
    ucs_status_t            status;

    if (ucs_unlikely(event->tgt_long.buffer_id ==
                     UCT_CXI_TAG_SEARCH_DELETE_SENTINEL)) {
        /* Our own SEARCH_AND_DELETE's found+deleted completion, not a
         * genuine priority-LE match -- see the sentinel's comment in
         * cxi_tag.h. Also caught by the generic bounds check below
         * (65535 is always >= max_outstanding), but logged distinctly
         * here for clarity while we're actively verifying this. */
        ucs_debug("cxi TAG [SEARCH-DELETE-ECHO] tag=0x%lx -- our own "
                 "SEARCH_AND_DELETE confirmation, not a real match",
                 (unsigned long)event->tgt_long.match_bits);
        return;
    }

    if (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) {
        ucs_debug("cxi TAG [OVF-MATCHED] slot=%d tag=0x%lx mlength=%u "
                 "rlength=%u -- overflow-buffered message matched to "
                 "this (later-posted) priority LE via search-on-append",
                 slot, (unsigned long)event->tgt_long.match_bits,
                 (unsigned)event->tgt_long.mlength,
                 (unsigned)event->tgt_long.rlength);
    } else {
        ucs_debug("cxi TAG [DIRECT-MATCH] slot=%d tag=0x%lx mlength=%u",
                 slot, (unsigned long)event->tgt_long.match_bits,
                 (unsigned)event->tgt_long.mlength);
    }

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale/racing event for an already-resolved slot -- e.g. UCP
         * force-cancelled this receive via the SW-matched path after the
         * hardware's own search-on-append raced our SEARCH_AND_DELETE.
         * Safe to drop; see file header. */
        ucs_debug("cxi TAG [MATCH-STALE] slot=%d already resolved, "
                 "dropping", slot);
        return;
    }

    ctx  = iface->tag.ctx[slot];
    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);

    stag    = event->tgt_long.match_bits;
    imm     = event->tgt_long.header_data;
    mlength = event->tgt_long.mlength;
    status  = (event->tgt_long.rlength > mlength) ? UCS_ERR_MESSAGE_TRUNCATED :
                                                    UCS_OK;

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    /* Both fire from this single event -- Cassini's direct match delivers
     * "matched" and "data placed" together, unlike a two-CQE model, so the
     * consumed-before-completed ordering UCP requires falls out trivially.
     * inline_data is always NULL: this is the true zero-copy case, data
     * already sits in the caller's own registered buffer. */
    ctx->tag_consumed_cb(ctx);
    ctx->completed_cb(ctx, stag, imm, mlength, NULL, status);
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

    ctx  = iface->tag.ctx[slot];
    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    if (!priv->cancel_force) {
        ctx->completed_cb(ctx, 0, 0, 0, NULL, UCS_ERR_CANCELED);
    }
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

    if (ucs_unlikely(iface->tag.free_count == 0)) {
        return UCS_ERR_EXCEEDS_LIMIT;
    }

    memh = (uct_cxi_mem_handle_t *)iov[0].memh;
    slot = iface->tag.free_list[--iface->tag.free_count];

    priv                    = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    priv->slot              = slot;
    priv->cancel_force      = 0;
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
    ucs_debug("cxi TAG [PRI-LE-POST] slot=%u tag=0x%lx tag_mask=0x%lx",
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

    priv->cancel_force = force ? 1 : 0;

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
