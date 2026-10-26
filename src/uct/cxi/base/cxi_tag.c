/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload: eager send/receive and native
 * rendezvous.
 *
 * One PTE (pid_offset = UCT_CXI_PTE_TAG, matching, long events) with two LE
 * populations (see cxi_tag.h): use_once priority LEs bound to the caller's
 * buffers for zero-copy direct matches, and an overflow-list ring for messages
 * with no receive posted yet, which are reported to UCP's software matching
 * immediately rather than retained.
 *
 * Send: short, bcopy and zcopy produce the same wire Put via ep->dfa_tag
 * (unrestricted, no rkey); imm travels in header_data.
 *
 * Repost and cancel timing:
 *   - The overflow ring is reposted when its terminal C_EVENT_PUT arrives with
 *     auto_unlinked (C_EVENT_UNLINK arrives too early to trigger it).
 *   - A priority-LE slot is freed by its first disposition event: a match, or
 *     C_EVENT_UNLINK with C_RC_OK. A cancel that loses to a match raises a
 *     second UNLINK with C_RC_ENTRY_NOT_FOUND, which is dropped (as libfabric's
 *     cxip_evtq_event_req()).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_tag.h"
#include "cxi_am.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_iov.inl>
#include <ucs/debug/log.h>
#include <ucs/sys/math.h>
#include <ucs/sys/string.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_tag_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

/* Plain host-memory pools -- the NIC never DMAs into or out of these
 * (software-Get tracking), so no registration is needed. */
static ucs_mpool_ops_t uct_cxi_tag_host_mpool_ops = {
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
 * Allocate the entries that hold unexpected messages until they are reported
 * (uct_cxi_unexp_report_t): one registered array of tag.unexp_max, the most the
 * credits let senders have outstanding (or tag.max_outstanding if more).
 * Registered because each entry is also the landing buffer of its address read
 * (LAC 0: the senders' RMA PTEs reach only that). Plus the streams (at most one
 * per entry) and the table to find them, sized so it never grows (khash can
 * still rehash when deleted keys pile up; a failed put is reported as a stream
 * that could not be made).
 */
static ucs_status_t
uct_cxi_iface_tag_unexp_init(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    size_t       page = ucs_get_page_size();
    size_t       len  = ucs_align_up(self->tag.unexp_max *
                                     sizeof(uct_cxi_unexp_report_t), page);
    ucs_status_t status;
    unsigned     i;
    int          ret;

    /* The fields that are looked at along a stream's chain share the first
     * cache line. */
    UCS_STATIC_ASSERT(ucs_offsetof(uct_cxi_unexp_report_t, flags) <
                      UCS_SYS_CACHE_LINE_SIZE);

    kh_init_inplace(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams);
    ucs_list_head_init(&self->tag.unexp_wait);
    ucs_list_head_init(&self->tag.unexp_live);
    self->tag.unexp_held        = 0;
    self->tag.unexp_seq         = 0;
    self->tag.unexp_ents        = NULL;
    self->tag.unexp_free        = NULL;
    self->tag.unexp_ents_len    = 0;
    self->tag.unexp_stream_pool = NULL;
    self->tag.unexp_stream_free = NULL;

    self->tag.unexp_stream_pool = ucs_calloc(self->tag.unexp_max,
                                             sizeof(uct_cxi_unexp_stream_t),
                                             "cxi-tag-unexp-streams");
    if (self->tag.unexp_stream_pool == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_streams;
    }
    for (i = 0; i < self->tag.unexp_max; i++) {
        self->tag.unexp_stream_pool[i].next_free =
                (i + 1 < self->tag.unexp_max) ?
                &self->tag.unexp_stream_pool[i + 1] : NULL;
    }
    self->tag.unexp_stream_free = &self->tag.unexp_stream_pool[0];
    if (kh_resize(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams,
                  2 * self->tag.unexp_max) < 0) {
        status = UCS_ERR_NO_MEMORY;
        goto err_streams;
    }

    ret = ucs_posix_memalign((void **)&self->tag.unexp_ents, page, len,
                             "cxi-tag-unexp-reports");
    if (ret != 0) {
        self->tag.unexp_ents = NULL;
        status               = UCS_ERR_NO_MEMORY;
        goto err_streams;
    }
    memset(self->tag.unexp_ents, 0, len);

    status = uct_cxi_do_map(lni, self->tag.unexp_ents, len,
                            UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
                            &self->tag.unexp_ents_mh);
    if (status != UCS_OK) {
        goto err_free;
    }
    if (self->tag.unexp_ents_mh.cxi_md->lac != 0) {
        ucs_error("cxi unexpected-report entries landed on lac %u; only lac "
                  "0 is supported",
                  (unsigned)self->tag.unexp_ents_mh.cxi_md->lac);
        uct_cxi_do_unmap(&self->tag.unexp_ents_mh);
        status = UCS_ERR_UNSUPPORTED;
        goto err_free;
    }

    self->tag.unexp_ents_len = len;
    for (i = 0; i < self->tag.unexp_max; i++) {
        self->tag.unexp_ents[i].next_free =
                (i + 1 < self->tag.unexp_max) ?
                &self->tag.unexp_ents[i + 1] : NULL;
    }
    self->tag.unexp_free = &self->tag.unexp_ents[0];
    return UCS_OK;

err_free:
    ucs_free(self->tag.unexp_ents);
    self->tag.unexp_ents = NULL;
err_streams:
    ucs_free(self->tag.unexp_stream_pool);
    self->tag.unexp_stream_pool = NULL;
    kh_destroy_inplace(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams);
    return status;
}

/* Entries still held are dropped silently, no callback at teardown. */
static void uct_cxi_iface_tag_unexp_cleanup(uct_cxi_iface_t *self)
{
    if (self->tag.unexp_ents == NULL) {
        return;
    }

    uct_cxi_do_unmap(&self->tag.unexp_ents_mh);
    ucs_free(self->tag.unexp_ents);
    self->tag.unexp_ents     = NULL;
    self->tag.unexp_free     = NULL;
    self->tag.unexp_ents_len = 0;
    ucs_free(self->tag.unexp_stream_pool);
    self->tag.unexp_stream_pool = NULL;
    self->tag.unexp_stream_free = NULL;
    kh_destroy_inplace(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams);
}

/* Build tag.recv_le, the priority LE of every posted receive but for the slot,
 * buffer and tag (filled by uct_cxi_iface_tag_recv_zcopy()). Needs tag.ptn. */
static void uct_cxi_iface_tag_init_recv_le(uct_cxi_iface_t *self)
{
    struct c_target_cmd *le = &self->tag.recv_le;

    le->command.opcode        = C_CMD_TGT_APPEND;
    le->ptl_list              = C_PTL_LIST_PRIORITY;
    le->ptlte_index           = self->tag.ptn;
    le->op_put                = 1;
    le->op_get                = 0;
    le->use_once              = 1;
    le->manage_local          = 1; /* mandatory even for a single-message LE:
                                    * makes Cassini ignore the initiator's
                                    * remote_offset (as libfabric) */
    le->unexpected_hdr_disable = 0; /* no effect on priority-list APPENDs;
                                     * left at the default */
    le->unrestricted_body_ro  = 1;
    le->unrestricted_end_ro   = 1;
    le->event_link_disable    = 1; /* no append-ack needed */
    le->event_unlink_disable  = 1; /* No event for the automatic use_once
                                    * unlink. The explicit UNLINK of
                                    * tag_recv_cancel() keeps its event, so
                                    * every priority-list C_EVENT_UNLINK is a
                                    * cancel confirmation. */
    le->no_truncate           = 0; /* allow truncated delivery so
                                   * UCS_ERR_TRUNCATED can be reported,
                                   * unlike AM which rejects outright */
    le->restart_seq           = 0;
    le->match_id              = CXI_MATCH_ID_ANY;
}

/* Append one overflow-list LE for ring buffer \a buf_idx: shaped like
 * uct_cxi_iface_post_am_le, with the flags of a real overflow list (see the
 * file header). */
static ucs_status_t
uct_cxi_iface_post_tag_ovf_le(uct_cxi_iface_t *self, int buf_idx,
                              int restart_seq)
{
    struct c_target_cmd le = {};
    ucs_status_t        status;

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
    le.min_free               = self->tag.max_msg;
    le.ignore_bits            = UINT64_MAX;
    le.match_bits             = 0;

    status = uct_cxi_iface_tgt_post(self, &le);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi TAG overflow LE APPEND buf %d: %s", buf_idx,
                  ucs_status_string(status));
        return status;
    }
    ucs_debug("cxi TAG overflow LE APPEND buf=%d ptn=%u start=0x%lx "
             "len=%zu restart_seq=%d", buf_idx, self->tag.pte->ptn,
             (unsigned long)le.start, self->tag.buf_size, restart_seq);
    return UCS_OK;
}

/*
 * Number and size of the overflow buffers. \a outstanding is the most bytes
 * peers may have sent and not had processed (active senders x tag byte window).
 *
 * As for the AM ring (uct_cxi_iface_size_am_ring, here without an 8-byte
 * header): messages are placed back to back and a buffer retires once less than
 * max_msg is left, so each takes at least (buf_size - max_msg) bytes. Messages
 * are processed in match order and a retired buffer is reposted after its last
 * message, so unprocessed bytes sit in the buffers after the current one. Allow
 * for those, the current buffer and one more linked:
 *
 *    num_bufs = floor(outstanding / (buf_size - max_msg)) + 2
 */
static void uct_cxi_iface_size_tag_ring(uct_cxi_iface_t *self,
                                        const uct_cxi_iface_config_t *config,
                                        size_t outstanding)
{
    size_t        max_msg  = self->tag.max_msg;
    size_t        min_size = 2 * max_msg;
    size_t        buf_size;
    unsigned long num_bufs;
    unsigned long needed;

    if (config->tag_ovf_buf_size != UCS_MEMUNITS_AUTO) {
        buf_size = config->tag_ovf_buf_size;
    } else {
        buf_size = ucs_max((size_t)UCT_CXI_TAG_OVF_BUF_SIZE_MIN,
                           UCT_CXI_TAG_OVF_BUF_PER_MSG * max_msg);
    }

    if (buf_size < min_size) {
        if (config->tag_ovf_buf_size != UCS_MEMUNITS_AUTO) {
            ucs_warn("cxi TAG_OVERFLOW_BUF_SIZE=%zu is too small for %zu-byte "
                     "messages: using %zu", buf_size, max_msg, min_size);
        }
        buf_size = min_size;
    }

    needed = outstanding / (buf_size - max_msg) + 2;

    if (config->tag_ovf_num_bufs == UCS_ULUNITS_AUTO) {
        num_bufs = needed;
    } else {
        num_bufs = config->tag_ovf_num_bufs;
        if (needed > num_bufs) {
            ucs_warn("cxi TAG_OVERFLOW_NUM_BUFS=%lu is below the %lu that "
                     "FC_ACTIVE_SENDERS peers at their full window need: the "
                     "ring can run out of buffers under load", num_bufs,
                     needed);
        }
    }

    if (num_bufs > UCT_CXI_TAG_OVF_NUM_BUFS_MAX) {
        ucs_warn("cxi tag overflow ring wants %lu buffers, limited to %u",
                 num_bufs, UCT_CXI_TAG_OVF_NUM_BUFS_MAX);
        num_bufs = UCT_CXI_TAG_OVF_NUM_BUFS_MAX;
    }

    /* A ring of one would have nothing linked while its buffer is being
     * reposted; that is for the user to ask for, not for sizing to derive. */
    if (config->tag_ovf_num_bufs == UCS_ULUNITS_AUTO) {
        num_bufs = ucs_max(num_bufs, 2ul);
    }
    self->tag.num_bufs = (unsigned)num_bufs;
    self->tag.buf_size = buf_size;
}

int uct_cxi_iface_tag_requested(const uct_cxi_iface_config_t *config,
                                const uct_iface_params_t *params)
{
    return (config->tag_enable != UCS_NO) &&
           ucs_test_all_flags(params->field_mask,
                              UCT_IFACE_PARAM_FIELD_HW_TM_EAGER_CB |
                              UCT_IFACE_PARAM_FIELD_HW_TM_RNDV_CB);
}

size_t uct_cxi_tag_max_msg(const uct_cxi_iface_config_t *config)
{
    return ucs_min(config->tag_eager_max, (size_t)UCT_CXI_AM_MAX_MSG_LIMIT);
}

ucs_status_t
uct_cxi_iface_open_tag_pte(uct_cxi_iface_t *self, struct cxil_lni *lni,
                           const uct_cxi_iface_config_t *config,
                           const uct_iface_params_t *params,
                           size_t slot_credits, size_t byte_credits)
{
    const union c_event *ev;
    ucs_status_t         status;
    int                  ret;
    unsigned             i;

    memset(&self->tag, 0, sizeof(self->tag));
    self->tag.ptn = -1;

    if (!uct_cxi_iface_tag_requested(config, params)) {
        /* No HW tag offload (UCP supplied no unexpected callbacks, or the
         * operator forced it off): tag.pte stays NULL, no TAG capability is
         * advertised and UCP matches in software over AM. Not an error. */
        return UCS_OK;
    }

    self->tag.eager_cb  = params->eager_cb;
    self->tag.eager_arg = params->eager_arg;
    self->tag.rndv_cb   = params->rndv_cb;
    self->tag.rndv_arg  = params->rndv_arg;

    /* UCT_CXI_TAG_MAX_OUTSTANDING_MAX leaves the two buffer_ids that
     * SEARCH_AND_DELETE and the fences use below the hardware's real 65535
     * ceiling. */
    self->tag.max_outstanding = ucs_min(config->tag_max_outstanding,
                                        UCT_CXI_TAG_MAX_OUTSTANDING_MAX);

    /* A message fits what is left of its buffer when that is at least min_free
     * (the largest message); a buffer of twice that holds one message before
     * retiring, as for the AM ring. */
    self->tag.max_msg = uct_cxi_tag_max_msg(config);
    if (self->tag.max_msg < config->tag_eager_max) {
        ucs_warn("cxi TAG_EAGER_MAX=%zu exceeds the %u bytes that min_free can "
                 "express: limiting the eager size to it",
                 config->tag_eager_max, UCT_CXI_AM_MAX_MSG_LIMIT);
    }
    uct_cxi_iface_size_tag_ring(self, config, byte_credits);

    /* Unexpected messages at once: each one the windows allow in the overflow
     * list holds at least an eager message's slots until reported; with small
     * windows, a receive per message is the most there are. */
    self->tag.unexp_max = ucs_max(self->tag.max_outstanding,
                                  slot_credits / UCT_CXI_FC_SLOTS_TAG_EAGER);
    if (self->tag.unexp_max > UCT_CXI_TAG_UNEXP_MAX_LIMIT) {
        ucs_warn("cxi TAG wants room for %zu unexpected messages, limited to "
                 "%u", self->tag.unexp_max, UCT_CXI_TAG_UNEXP_MAX_LIMIT);
        self->tag.unexp_max = UCT_CXI_TAG_UNEXP_MAX_LIMIT;
    }

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

    /* The posted receives that can still take an unexpected message. */
    self->tag.pend     = ucs_calloc(UCT_CXI_TAG_PEND_SIZE,
                                    sizeof(*self->tag.pend), "cxi-tag-pend");
    self->tag.slot_pos = ucs_calloc(self->tag.max_outstanding,
                                    sizeof(*self->tag.slot_pos),
                                    "cxi-tag-slot-pos");
    self->tag.fences   = ucs_calloc(UCT_CXI_TAG_PEND_SIZE,
                                    sizeof(*self->tag.fences), "cxi-tag-fences");
    if ((self->tag.pend == NULL) || (self->tag.slot_pos == NULL) ||
        (self->tag.fences == NULL)) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_pend;
    }
    self->tag.fence_interval = ucs_max(config->tag_fence_interval, 1u);

    /* Per-peer unexpected-rndv header cache -- see uct_cxi_rndv_peer_hdr_t
     * in cxi_iface.h. Growable, starts empty; never fails to init. */
    kh_init_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
    kh_init_inplace(uct_cxi_eager_pair_hash, &self->tag.eager_pairs);
    if (kh_resize(uct_cxi_eager_pair_hash, &self->tag.eager_pairs,
                  self->tag.unexp_max) < 0) {
        /* Never more messages wait for their other event than are unexpected;
         * sized for all of them, a put does not have to allocate. */
        status = UCS_ERR_NO_MEMORY;
        goto err_free_rndv_peer_cache;
    }

    /* Pool of software-issued rendezvous Gets (uct_cxi_rdzv_get_op_t), capped
     * like max_outstanding. */
    {
        ucs_mpool_params_t mp_params;
        unsigned           grow = ucs_min(64u, self->tag.max_outstanding);

        ucs_mpool_params_reset(&mp_params);
        mp_params.elem_size       = sizeof(uct_cxi_rdzv_get_op_t);
        mp_params.elems_per_chunk = ucs_max(grow, 1u);
        mp_params.max_elems       = self->tag.max_outstanding;
        mp_params.ops             = &uct_cxi_tag_host_mpool_ops;
        mp_params.name            = "cxi-tag-rdzv-get-op";
        status = ucs_mpool_init(&mp_params, &self->tag.rdzv_get_op_pool);
        if (status != UCS_OK) {
            goto err_free_rndv_peer_cache;
        }
    }

    /* Unexpected messages held before they are reported -- see
     * uct_cxi_unexp_report_t in cxi_tag.h. */
    status = uct_cxi_iface_tag_unexp_init(self, lni);
    if (status != UCS_OK) {
        goto err_cleanup_rdzv_get_op_pool;
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
            goto err_free_rndv_peer_cache;
        }
        status = uct_cxi_do_map(lni, self->tag.rx_base, total,
                                UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
                                &self->tag.rx_mh);
        if (status != UCS_OK) {
            ucs_free(self->tag.rx_base);
            self->tag.rx_base = NULL;
            goto err_free_rndv_peer_cache;
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
        ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts, &self->tag.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte TAG: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_rx;
    }
    self->tag.ptn = self->tag.pte->ptn;
    uct_cxi_iface_tag_init_recv_le(self);

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
            while ((ev = cxi_eq_get_event(self->rx_eq.evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(self->rx_eq.evtq);
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
    ucs_info("cxi TAG ring: %u buffers of %zu bytes, min_free %zu; %zu "
             "unexpected messages, %u posted receives",
             self->tag.num_bufs, self->tag.buf_size, self->tag.max_msg,
             self->tag.unexp_max, self->tag.max_outstanding);
    ucs_debug("cxi TAG PTE ptn %u enabled", self->tag.pte->ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(self->tag.pte_map);
    self->tag.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(self->tag.pte);
    self->tag.pte = NULL;
    self->tag.ptn = -1;
    ucs_free(self->tag.ovf_repost_pending);
    self->tag.ovf_repost_pending = NULL;
err_free_ovf_refcnt:
    ucs_free(self->tag.ovf_refcnt);
    self->tag.ovf_refcnt = NULL;
err_unmap_rx:
    uct_cxi_do_unmap(&self->tag.rx_mh);
    ucs_free(self->tag.rx_base);
    self->tag.rx_base = NULL;
    uct_cxi_iface_tag_unexp_cleanup(self);
err_cleanup_rdzv_get_op_pool:
    ucs_mpool_cleanup(&self->tag.rdzv_get_op_pool, 1);
err_free_rndv_peer_cache:
    kh_destroy_inplace(uct_cxi_eager_pair_hash, &self->tag.eager_pairs);
    kh_destroy_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
err_free_pend:
    ucs_free(self->tag.fences);
    ucs_free(self->tag.slot_pos);
    ucs_free(self->tag.pend);
    self->tag.fences   = NULL;
    self->tag.slot_pos = NULL;
    self->tag.pend     = NULL;
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
    self->tag.ptn = -1;
    uct_cxi_do_unmap(&self->tag.rx_mh);
    ucs_free(self->tag.rx_base);
    ucs_free(self->tag.ovf_repost_pending);
    ucs_free(self->tag.ovf_refcnt);

    ucs_mpool_cleanup(&self->tag.rdzv_get_op_pool, 1);
    uct_cxi_iface_tag_unexp_cleanup(self);
    kh_destroy_inplace(uct_cxi_eager_pair_hash, &self->tag.eager_pairs);
    kh_destroy_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
    ucs_free(self->tag.fences);
    ucs_free(self->tag.slot_pos);
    ucs_free(self->tag.pend);
    ucs_free(self->tag.cancel_ctx);
    ucs_free(self->tag.free_list);
    ucs_free(self->tag.ctx);
}


/* The address table (iface->rdzv.addr_table): one registered slot per 8-bit
 * rendezvous id, so a peer's read never falls outside it. LAC 0, as the RMA PTE
 * it is read through. */
static ucs_status_t
uct_cxi_iface_rdzv_table_init(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    size_t       page = ucs_get_page_size();
    size_t       len  = ucs_align_up(UCT_CXI_RDZV_MAX_OUTSTANDING_MAX *
                                     sizeof(uint64_t), page);
    ucs_status_t status;
    int          ret;

    self->rdzv.addr_table     = NULL;
    self->rdzv.addr_table_len = 0;

    ret = ucs_posix_memalign((void **)&self->rdzv.addr_table, page, len,
                             "cxi-rdzv-addr-table");
    if (ret != 0) {
        self->rdzv.addr_table = NULL;
        return UCS_ERR_NO_MEMORY;
    }
    memset(self->rdzv.addr_table, 0, len);

    status = uct_cxi_do_map(lni, self->rdzv.addr_table, len,
                            UCT_DMABUF_FD_INVALID, 0, UCS_MEMORY_TYPE_HOST,
                            &self->rdzv.addr_table_mh);
    if (status != UCS_OK) {
        goto err_free;
    }
    if (self->rdzv.addr_table_mh.cxi_md->lac != 0) {
        ucs_error("cxi rendezvous address table landed on lac %u; only lac "
                  "0 is supported",
                  (unsigned)self->rdzv.addr_table_mh.cxi_md->lac);
        uct_cxi_do_unmap(&self->rdzv.addr_table_mh);
        status = UCS_ERR_UNSUPPORTED;
        goto err_free;
    }

    self->rdzv.addr_table_len = len;
    return UCS_OK;

err_free:
    ucs_free(self->rdzv.addr_table);
    self->rdzv.addr_table = NULL;
    return status;
}

static void uct_cxi_iface_rdzv_table_cleanup(uct_cxi_iface_t *self)
{
    if (self->rdzv.addr_table == NULL) {
        return;
    }

    uct_cxi_do_unmap(&self->rdzv.addr_table_mh);
    ucs_free(self->rdzv.addr_table);
    self->rdzv.addr_table     = NULL;
    self->rdzv.addr_table_len = 0;
}

/*
 * Open the rendezvous source-exposure PTE: matching mode, one persistent
 * wildcard LE over the whole address range, as libfabric's default rendezvous
 * source PTE. Matching mode only puts the Get on the wire format that carries
 * match_bits, for O(1) id correlation (see uct_cxi_rdzv_op_t). op_get only: it
 * is never Put to. LAC 0, opened only when tag offload is enabled.
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
    self->rdzv.ptn = -1;

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

    status = uct_cxi_iface_rdzv_table_init(self, lni);
    if (status != UCS_OK) {
        goto err_free_ids;
    }

    {
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching = 1,
            .en_flowctrl = 1
        };
        ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts, &self->rdzv.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte RDZV: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_free_ids;
    }
    self->rdzv.ptn = self->rdzv.pte->ptn;

    /* pid_idx must be the device's rdzv_get_idx: a NIC-auto-issued rendezvous
     * Get targets that fixed value (anything else gives C_RC_PTLTE_NOT_FOUND).
     * Unlike every other PTE here software does not choose it; libfabric reads
     * the same field. */
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
            while ((ev = cxi_eq_get_event(self->rx_eq.evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(self->rx_eq.evtq);
        }
    }

    /* The whole-LAC catch-all LE: fully wildcarded and unrestricted-flavored
     * (unrestricted_body_ro/end_ro), as libfabric's default one. */
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
                                                      * (the zero default
                                                      * matches one bogus
                                                      * identity) */
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
    self->rdzv.ptn = -1;
err_free_ids:
    uct_cxi_iface_rdzv_table_cleanup(self);
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
    self->rdzv.ptn = -1;
    uct_cxi_iface_rdzv_table_cleanup(self);
    ucs_free(self->rdzv.free_ids);
    self->rdzv.free_ids = NULL;
    ucs_free(self->rdzv.ops);
    self->rdzv.ops = NULL;
}


/* -------------------------------------------------------------------------
 * Event dispatch (called from cxi_iface.c's iface_progress())
 * -------------------------------------------------------------------------
 */

/* Locate the overflow buffer and the data pointer for an event's
 * tgt_long.start, for events that carry only an address (a delayed match, or an
 * arrival reported later from a copy of its event). */
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
 * Repost this buffer generation once its refcnt reads exactly 0 and a repost
 * is pending. Checked from the increment side (tag_handle_ovf_arrival) as well
 * as the decrement (uct_cxi_iface_tag_ovf_release): a decrement can land before
 * its increment (seen on hardware), and then the increment, possibly the
 * generation's last arrival, is what brings refcnt to 0.
 */
static void
uct_cxi_iface_tag_ovf_maybe_repost(uct_cxi_iface_t *iface, int buf_idx)
{
    if ((iface->tag.ovf_refcnt[buf_idx] == 0) &&
        iface->tag.ovf_repost_pending[buf_idx]) {
        iface->tag.ovf_repost_pending[buf_idx] = 0;
        uct_cxi_iface_post_tag_ovf_le(iface, buf_idx, 1);
    }
}

/*
 * Drop one reference on an overflow buffer generation (ovf_refcnt,
 * cxi_iface.h). Call only when the resolving event's mlength > 0 (as the
 * increment), from the handler that reads that arrival's payload:
 * uct_cxi_iface_tag_report_unexp_eager() when the message goes to UCP, or
 * tag_handle_eager_match() when a delayed match copies it (including its
 * force-cancel branch, which reports to UCP). Never from a SEARCH_AND_DELETE
 * outcome: it reads no overflow memory.
 *
 * No assert that refcnt > 0: a decrement landing before its increment is real
 * (see uct_cxi_iface_tag_ovf_maybe_repost()); refcnt is signed for it.
 */
static inline void
uct_cxi_iface_tag_ovf_release(uct_cxi_iface_t *iface, int buf_idx)
{
    iface->tag.ovf_refcnt[buf_idx]--;
    uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
}

/*
 * Return the credits \a initiator was charged for a message that went to the
 * overflow list (which the target tracks): \a slots and the buffer space of its
 * \a length bytes as sent (a receive posted too small takes fewer, but the
 * sender was charged all). A sender without flow control has no record and was
 * charged nothing. A message that matched a posted receive is never tracked.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_tag_credit_return(uct_cxi_iface_t *iface, uint32_t initiator,
                          unsigned slots, uint32_t length)
{
#ifndef UCT_CXI_DISABLE_FC
    uct_cxi_peer_t *peer;

    if (ucs_likely(iface->fc.enabled)) {
        peer = uct_cxi_fc_rx_peer(iface, initiator);
        if (peer != NULL) {
            uct_cxi_fc_rx_done(iface, peer, UCT_CXI_FC_TAG, slots, length);
        }
    }
#endif
}

/*
 * An unexpected eager message is done with: release its overflow buffer
 * reference (\a buf_idx, -1 if it has no data there) and return its sender's
 * credits. They end together: the message is out of the NIC's unexpected list
 * and its data copied out or given up. Release first, so the credit is never
 * back before the buffer can be reused.
 */
static void uct_cxi_tag_ovf_done(uct_cxi_iface_t *iface, int buf_idx,
                                 uint32_t initiator, uint32_t length)
{
    if (buf_idx >= 0) {
        uct_cxi_iface_tag_ovf_release(iface, buf_idx);
    }
    uct_cxi_tag_credit_return(iface, initiator, UCT_CXI_FC_SLOTS_TAG_EAGER,
                              length);
}

/*
 * Report an unexpected eager message (or software rendezvous request) to UCP
 * from the event of its arrival or a copy of it: at once, or later if it waits
 * behind an unexpected rendezvous of the same sender
 * (uct_cxi_tag_found_eager()).
 *
 * eager_cb (rndv_cb for a request) gets the message where it sits in the
 * overflow buffer; this arrival's reference is held during the call and
 * released after, with the sender's credits. The buffer and bytes are found
 * from event->tgt_long.start; the SEARCH_AND_DELETE that removes the message
 * from the NIC's list has no part in this.
 */
static void
uct_cxi_iface_tag_report_unexp_eager(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    uint32_t len      = event->tgt_long.mlength;
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    uint32_t sent_len  = event->tgt_long.rlength;
    /* Find the buffer from where the message sits, not the command's buffer_id:
     * the SEARCH_AND_DELETE took the oldest entry with this tag, which need not
     * be this arrival, and the reference to release is that message's own. */
    int      buf_idx = (len > 0) ? uct_cxi_iface_tag_ovf_buf_idx(
                                           iface, event->tgt_long.start) : -1;
    uint64_t tag      = event->tgt_long.match_bits;
    uint64_t imm      = event->tgt_long.header_data;
    void    *context = NULL;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /* Not expected with use_once=1. Release rather than leak if it happens
         * (only if mlength > 0, as the increment). No credits go back: no
         * message was taken off the list, and the one still there will give
         * them back. */
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

    ucs_info("cxi TAG [SEARCH-DELETE-MATCH] tag=0x%lx len=%u buf_idx=%d",
             (unsigned long)tag, len, buf_idx);

    /* Hand eager_cb the payload in place in the overflow ring. With no
     * UCT_CB_PARAM_FLAG_DESC it must copy what it keeps (UCP does). The
     * arrival's reference is held during the call, so no repost can overwrite
     * the payload even if eager_cb re-enters progress; release only afterwards.
     * Nothing after the call may read \a event: re-entrant progress can
     * recycle its slot in the event queue. */
    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        /* A software rendezvous request: UCP's RTS is the payload, and there
         * is no remote address (UCP tells it from a rendezvous the NIC
         * pulls). UCP copies it, as it does an eager message (no DESC flag). */
        (void)iface->tag.rndv_cb(iface->tag.rndv_arg, 0, tag,
                                 uct_cxi_iface_tag_ovf_data(
                                         iface, buf_idx,
                                         event->tgt_long.start),
                                 len, 0, 0, NULL);
    } else {
        (void)iface->tag.eager_cb(iface->tag.eager_arg,
                                  (len > 0) ? uct_cxi_iface_tag_ovf_data(
                                          iface, buf_idx,
                                          event->tgt_long.start) : NULL,
                                  len, UCT_CB_PARAM_FLAG_FIRST, tag, imm,
                                  &context);
    }

    /* Copied out by eager_cb: the sender's credits are free to go back. */
    uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
}

/* -------------------------------------------------------------------------
 * Posted receives that can still take an unexpected message (see
 * uct_cxi_tag_pend_t in cxi_iface.h)
 * -------------------------------------------------------------------------
 */

#define UCT_CXI_TAG_PEND_MASK  (UCT_CXI_TAG_PEND_SIZE - 1u)

/* Is the receive counted \a pos still in the window of the ring? */
static UCS_F_ALWAYS_INLINE int
uct_cxi_tag_pend_in_window(const uct_cxi_iface_t *iface, uint32_t pos)
{
    return (uint32_t)(pos - iface->tag.pend_tail) <
           (uint32_t)(iface->tag.pend_head - iface->tag.pend_tail);
}

/*
 * The outcome of the receive on \a slot is known (a match, a cancel): it has no
 * message to take. Returns its previous state, or UCT_CXI_TAG_PEND_FREE if the
 * ring no longer has it.
 */
static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_tag_pend_spent(uct_cxi_iface_t *iface, unsigned slot)
{
    uint32_t            pos = iface->tag.slot_pos[slot];
    uct_cxi_tag_pend_t *e;
    unsigned            prev;

    if (!uct_cxi_tag_pend_in_window(iface, pos)) {
        return UCT_CXI_TAG_PEND_FREE;
    }

    e         = &iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK];
    prev      = e->state;
    e->state  = UCT_CXI_TAG_PEND_SPENT;
    return prev;
}

/*
 * A message with \a tag arrived in the overflow list and no receive has matched
 * it yet. Hardware gives it to the first receive appended after it landed whose
 * tag matches; one appended before would have taken it on arrival. So the
 * ring's PENDING receives that match were all appended after it, and the first
 * is claimed. UCP is told it is taken now (tag_consumed_cb), before it could
 * match that receive to another message: the NIC has already given the receive
 * its message and the match event is still to come (as the RC transports do).
 * The tell is made once; the match event finds UCT_CXI_TAG_FLAG_CONSUMED.
 * Returns 1 if a receive was claimed.
 */
static int uct_cxi_tag_claim(uct_cxi_iface_t *iface, uint64_t tag)
{
    uint32_t                n;
    uct_cxi_tag_pend_t     *e;
    uct_tag_context_t      *ctx;
    uct_cxi_tag_ctx_priv_t *priv;

    for (n = iface->tag.pend_tail; n != iface->tag.pend_head; ++n) {
        e = &iface->tag.pend[n & UCT_CXI_TAG_PEND_MASK];
        if ((e->state != UCT_CXI_TAG_PEND_PENDING) ||
            (((tag ^ e->tag) & e->mask) != 0)) {
            continue;
        }

        ctx = iface->tag.ctx[e->slot];
        ucs_assert(ctx != NULL);
        ucs_assert(!iface->tag.cancel_ctx[e->slot].force);
        priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
        ucs_assert(!(priv->rndv_flags & UCT_CXI_TAG_FLAG_CONSUMED));

        e->state          = UCT_CXI_TAG_PEND_CLAIMED;
        priv->rndv_flags |= UCT_CXI_TAG_FLAG_CONSUMED;
        ucs_debug("cxi TAG [CLAIM] tag=0x%lx by slot=%u (pos %u)",
                  (unsigned long)tag, (unsigned)e->slot, n);
        ctx->tag_consumed_cb(ctx);
        return 1;
    }

    return 0;
}

/*
 * Post a fence: a search that matches nothing (as libfabric's
 * cxip_flush_appends(): all-ones match bits, a match_id no sender has, length
 * 0). The command queue is in order, so its event follows the events of every
 * earlier append; the ring's window moves up to it when it is seen
 * (uct_cxi_iface_tag_fence_done()). Not posted when the most are in flight or
 * the queue is wedged; retried with the next receive.
 */
static void uct_cxi_tag_fence_post(uct_cxi_iface_t *iface)
{
    struct c_target_cmd cmd = {};

    if ((iface->tag.fence_head - iface->tag.fence_tail) >=
        UCT_CXI_TAG_FENCE_MAX_INFLIGHT) {
        return;
    }

    cmd.command.opcode = C_CMD_TGT_SEARCH;
    cmd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    cmd.ptlte_index    = iface->tag.ptn;
    cmd.match_bits     = -1UL;
    cmd.length         = 0;
    cmd.buffer_id      = UCT_CXI_TAG_FENCE_BUFFER_ID;

    if (uct_cxi_iface_tgt_post(iface, &cmd) != UCS_OK) {
        return;
    }

    iface->tag.fences[iface->tag.fence_head++ & UCT_CXI_TAG_PEND_MASK] =
            iface->tag.pend_head;
    iface->tag.fence_posts = 0;
}

/* The event of the oldest fence in flight: its receives are appended. */
void uct_cxi_iface_tag_fence_done(uct_cxi_iface_t *iface,
                                  const union c_event *event)
{
    if (ucs_unlikely(iface->tag.fence_head == iface->tag.fence_tail)) {
        ucs_error("cxi TAG a fence event with no fence in flight, rc=%d",
                  cxi_event_rc(event));
        return;
    }

    iface->tag.pend_tail =
            iface->tag.fences[iface->tag.fence_tail++ & UCT_CXI_TAG_PEND_MASK];
}

/* -------------------------------------------------------------------------
 * Held unexpected reports (see uct_cxi_unexp_report_t in cxi_tag.h)
 * -------------------------------------------------------------------------
 */

static void uct_cxi_unexp_read_comp(uct_cxi_send_op_t *op, ucs_status_t status);
static void uct_cxi_tag_found_eager(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint64_t seq);

/* The stream of \a initiator's messages with \a tag, NULL if none of them is
 * held. */
static uct_cxi_unexp_stream_t *
uct_cxi_unexp_stream_find(uct_cxi_iface_t *iface, uint32_t initiator,
                          uint64_t tag)
{
    uct_cxi_unexp_key_t key = {};
    khiter_t            k;

    key.tag       = tag;
    key.initiator = initiator;
    k = kh_get(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, key);
    return (k == kh_end(&iface->tag.unexp_streams)) ? NULL :
           kh_value(&iface->tag.unexp_streams, k);
}

/* As above, making the stream if there is none. NULL if all are in use. */
static uct_cxi_unexp_stream_t *
uct_cxi_unexp_stream_get(uct_cxi_iface_t *iface, uint32_t initiator,
                         uint64_t tag)
{
    uct_cxi_unexp_stream_t *stream = uct_cxi_unexp_stream_find(iface, initiator,
                                                               tag);
    uct_cxi_unexp_key_t     key    = {};
    khiter_t                k;
    int                     ret;

    if (stream != NULL) {
        return stream;
    }

    stream = iface->tag.unexp_stream_free;
    if (stream == NULL) {
        return NULL;
    }

    key.tag       = tag;
    key.initiator = initiator;
    k = kh_put(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, key,
               &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        return NULL;
    }

    iface->tag.unexp_stream_free = stream->next_free;
    kh_value(&iface->tag.unexp_streams, k) = stream;
    ucs_list_add_tail(&iface->tag.unexp_live, &stream->live);
    ucs_list_head_init(&stream->entries);
    stream->tag       = tag;
    stream->initiator = initiator;
    stream->num_lost  = 0;
    stream->busy      = 0;
    return stream;
}

/* Give back a stream with nothing left in it, unless it is being advanced:
 * that is the end of that, and the one to do it. */
static void uct_cxi_unexp_stream_put(uct_cxi_iface_t *iface,
                                     uct_cxi_unexp_stream_t *stream)
{
    uct_cxi_unexp_key_t key = {};
    khiter_t            k;

    if (stream->busy || !ucs_list_is_empty(&stream->entries)) {
        return;
    }

    key.tag       = stream->tag;
    key.initiator = stream->initiator;
    k = kh_get(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, key);
    ucs_assert(k != kh_end(&iface->tag.unexp_streams));
    kh_del(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, k);
    ucs_list_del(&stream->live);

    stream->next_free            = iface->tag.unexp_stream_free;
    iface->tag.unexp_stream_free = stream;
}

/* Take an entry for \a event (with \a flags already seen) and chain it in its
 * stream where \a seq, its arrival number, puts it: at the end unless a later
 * arrival already has an entry (an eager message is held only once its
 * SEARCH_AND_DELETE finds it, possibly after a later rendezvous). NULL if all
 * entries or streams are in use. */
static uct_cxi_unexp_report_t *
uct_cxi_unexp_alloc(uct_cxi_iface_t *iface, const union c_event *event,
                    int is_rndv, uint8_t flags, uint64_t seq)
{
    ucs_list_link_t        *pos;
    uct_cxi_unexp_report_t *e = iface->tag.unexp_free;
    uct_cxi_unexp_stream_t *stream;

    if (e == NULL) {
        return NULL;
    }

    stream = uct_cxi_unexp_stream_get(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);
    if (stream == NULL) {
        return NULL;
    }

    iface->tag.unexp_free = e->next_free;
    e->op.ep              = NULL;
    e->op.comp            = NULL;
    e->op.handler         = uct_cxi_unexp_read_comp;
    e->iface              = iface;
    e->event              = *event;
    e->stream             = stream;
    e->initiator          = stream->initiator;
    e->tag                = stream->tag;
    e->rendezvous_id      = event->tgt_long.rendezvous_id;
    e->is_rndv            = is_rndv;
    e->state              = is_rndv ? UCT_CXI_UNEXP_NEW : UCT_CXI_UNEXP_READY;
    e->flags              = flags;
    e->value              = 0;
    e->seq                = seq;
    ucs_list_head_init(&e->wait);
    pos = stream->entries.prev;
    while ((pos != &stream->entries) &&
           (ucs_container_of(pos, uct_cxi_unexp_report_t, link)->seq > seq)) {
        pos = pos->prev;
    }
    ucs_list_insert_after(pos, &e->link);
    stream->num_lost += !!(flags & UCT_CXI_UNEXP_LOST);
    iface->tag.unexp_held += is_rndv;
    return e;
}

/* Take an entry off its chain; it is not free until uct_cxi_unexp_free(), and
 * its stream, if now empty, is the caller's to give back. */
static void uct_cxi_unexp_unlink(uct_cxi_iface_t *iface,
                                 uct_cxi_unexp_report_t *e)
{
    ucs_list_del(&e->link);
    e->stream->num_lost -= !!(e->flags & UCT_CXI_UNEXP_LOST);
    iface->tag.unexp_held -= e->is_rndv;
    if (!ucs_list_is_empty(&e->wait)) {
        ucs_list_del(&e->wait);
        ucs_list_head_init(&e->wait);
    }
}

/*
 * Give back an entry that is off its chain. For a rendezvous this is where the
 * sender's credits go back: all its events have been handled by now (its
 * arrival and its address read, or for a message a receive took, the arrival
 * last: uct_cxi_unexp_arrival_lost()). Every way out of the table ends here, so
 * the credits go back once.
 */
static void uct_cxi_unexp_free(uct_cxi_iface_t *iface,
                               uct_cxi_unexp_report_t *e)
{
    if (e->is_rndv) {
        uct_cxi_tag_credit_return(iface, e->initiator,
                                  UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
    }

    e->next_free          = iface->tag.unexp_free;
    iface->tag.unexp_free = e;
}

/* An entry with nothing to wait for or report: a tombstone whose message
 * arrived, or one that could not be handed on. Its address read is not posted:
 * only a reported entry is read. */
static void uct_cxi_unexp_discard(uct_cxi_iface_t *iface,
                                  uct_cxi_unexp_report_t *e)
{
    ucs_assert(e->state != UCT_CXI_UNEXP_READING);
    uct_cxi_unexp_unlink(iface, e);
    uct_cxi_unexp_free(iface, e);
}

/* The first entry of \a stream that is not a tombstone, NULL if none. */
static uct_cxi_unexp_report_t *
uct_cxi_unexp_head(uct_cxi_unexp_stream_t *stream)
{
    uct_cxi_unexp_report_t *e;

    ucs_list_for_each(e, &stream->entries, link) {
        if (!(e->flags & UCT_CXI_UNEXP_LOST)) {
            return e;
        }
    }
    return NULL;
}

/* Is an entry of \a stream that is arrived earlier than \a seq still held (not
 * a tombstone)? Then a message with that number must wait behind it. */
static int uct_cxi_unexp_has_older(uct_cxi_unexp_stream_t *stream,
                                   uint64_t seq)
{
    uct_cxi_unexp_report_t *e;

    ucs_list_for_each(e, &stream->entries, link) {
        if (!(e->flags & UCT_CXI_UNEXP_LOST) && (e->seq < seq)) {
            return 1;
        }
    }
    return 0;
}

/*
 * Post the read of the source address of \a e's rendezvous: 8 bytes from slot
 * rendezvous_id of the sender's address table, with the restricted RMA Get any
 * endpoint would use (LAC 0, pid_offset 0). The sender's address comes from the
 * event's initiator (tag receives have no endpoint) and the table base from its
 * announce. Waits only for command queue room, as for any command posted from a
 * handler. The REPLY is on the RX queue, like other handler-issued Gets (which
 * cannot be refused for lack of a TX slot). UCS_ERR_NO_ELEM: its announce has
 * not been seen.
 */
static ucs_status_t uct_cxi_unexp_start_read(uct_cxi_iface_t *iface,
                                             uct_cxi_unexp_report_t *e)
{
    uct_cxi_md_t                  *md = uct_cxi_iface_md(iface);
    khiter_t                       k  = kh_get(uct_cxi_rndv_peer_hash,
                                               &iface->tag.rndv_peer_cache,
                                               e->initiator);
    const uct_cxi_rndv_peer_hdr_t *peer;
    struct c_full_dma_cmd          cmd = {};
    union c_fab_addr               dfa;
    uint8_t                        idx_ext;
    ucs_time_t                     deadline;
    int                            ret;

    if (k == kh_end(&iface->tag.rndv_peer_cache)) {
        return UCS_ERR_NO_ELEM;
    }
    peer = &kh_value(&iface->tag.rndv_peer_cache, k);

    cxi_build_dfa(CXI_MATCH_ID_EP(md->pid_bits, e->initiator),
                  CXI_MATCH_ID_PID(md->pid_bits, e->initiator), md->pid_bits,
                  0 /* the RMA PTE of LAC 0 */, &dfa, &idx_ext);

    cmd.command.opcode     = C_CMD_GET;
    cmd.index_ext          = idx_ext;
    cmd.lac                = iface->tag.unexp_ents_mh.cxi_md->lac;
    cmd.event_send_disable = 1;
    cmd.restricted         = 1;
    cmd.eq                 = iface->rx_eq.evtq->eqn;
    cmd.dfa                = dfa;
    cmd.remote_offset      = peer->table_iova +
                             (uint64_t)e->event.tgt_long.rendezvous_id *
                             sizeof(uint64_t);
    cmd.local_addr         = iface->tag.unexp_ents_mh.iova_offset +
                             (uint64_t)(uintptr_t)&e->value;
    cmd.request_len        = sizeof(e->value);
    cmd.user_ptr           = (uint64_t)(uintptr_t)e;

    deadline = ucs_get_time() + ucs_time_from_sec(UCT_CXI_TGT_CMDQ_TIMEOUT_SEC);
    do {
        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    } while ((ret == -ENOSPC) && (ucs_get_time() < deadline));
    if (ucs_unlikely(ret != 0)) {
        return UCS_ERR_IO_ERROR;
    }

    cxi_cq_ring(iface->tx.cmdq);
    return UCS_OK;
}

/* Post the address read of rendezvous \a e if it can be (not yet posted,
 * sender known); otherwise it waits for the announce handler. */
static void uct_cxi_unexp_start(uct_cxi_iface_t *iface,
                                uct_cxi_unexp_report_t *e)
{
    ucs_status_t status;

    ucs_assert(!(e->flags & UCT_CXI_UNEXP_LOST));
    if (!e->is_rndv || (e->state != UCT_CXI_UNEXP_NEW) ||
        !ucs_list_is_empty(&e->wait)) {
        return;
    }

    status = uct_cxi_unexp_start_read(iface, e);
    if (status == UCS_OK) {
        e->state = UCT_CXI_UNEXP_READING;
    } else if (status == UCS_ERR_NO_ELEM) {
        ucs_list_add_tail(&iface->tag.unexp_wait, &e->wait);
    } else {
        ucs_error("cxi TAG cannot read the source address of an unexpected "
                  "rendezvous: %s", ucs_status_string(status));
        e->state = UCT_CXI_UNEXP_FAILED;
    }
}

/* Can \a e be reported to UCP, as far as it itself goes? A rendezvous must
 * have its address (or know it can not get it). */
static UCS_F_ALWAYS_INLINE int
uct_cxi_unexp_is_ready(const uct_cxi_unexp_report_t *e)
{
    return !e->is_rndv || (e->state == UCT_CXI_UNEXP_READY) ||
           (e->state == UCT_CXI_UNEXP_FAILED);
}

/*
 * Report \a e, which is off its stream's chain, to UCP and give it back.
 * Released first and reported from copies, as the callback may re-enter
 * progress.
 *
 * For a rendezvous, rndv_cb gets:
 *   - header: this sender's cached {ep_id, md_index} plus the message's req_id
 *     (header_data);
 *   - remote_addr: the source address read from the sender's table;
 *   - rkey_buf: a stack uct_cxi_rkey_t with is_rndv and rendezvous_id, enough
 *     for UCP's later get to reach the sender's rendezvous source PTE through
 *     its own uct_ep (there is no real memory key).
 * flags=0, as uct_rc_mlx5_handle_unexp_rndv(): a report is never fragmented.
 */
static void uct_cxi_unexp_report(uct_cxi_iface_t *iface,
                                 uct_cxi_unexp_report_t *e)
{
    union c_event            event   = e->event;
    uint64_t                 addr    = e->value;
    int                      is_rndv = e->is_rndv;
    int                      failed  = (e->state == UCT_CXI_UNEXP_FAILED);
    uct_cxi_rndv_hdr_wire_t  hdr;
    uct_cxi_rkey_t           rkey    = {};
    khiter_t                 k;

    uct_cxi_unexp_free(iface, e);

    if (!is_rndv) {
        uct_cxi_iface_tag_report_unexp_eager(iface, &event);
        return;
    }

    if (failed) {
        ucs_error("cxi TAG unexpected rendezvous tag=0x%lx dropped: the "
                  "source address could not be read from its sender",
                  (unsigned long)event.tgt_long.match_bits);
        return;
    }

    k = kh_get(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache,
               event.tgt_long.initiator.initiator.process);
    ucs_assert(k != kh_end(&iface->tag.rndv_peer_cache));
    hdr.ep_id    = kh_value(&iface->tag.rndv_peer_cache, k).ep_id;
    hdr.md_index = kh_value(&iface->tag.rndv_peer_cache, k).md_index;
    hdr.req_id   = event.tgt_long.header_data;

    rkey.is_rndv       = 1;
    rkey.rendezvous_id = event.tgt_long.rendezvous_id;

    ucs_info("cxi TAG [RNDV-REPORT] tag=0x%lx rlength=%u rendezvous_id=%u "
             "addr=0x%lx", (unsigned long)event.tgt_long.match_bits,
             (unsigned)event.tgt_long.rlength, (unsigned)rkey.rendezvous_id,
             (unsigned long)addr);

    (void)iface->tag.rndv_cb(iface->tag.rndv_arg, 0,
                             event.tgt_long.match_bits, &hdr, sizeof(hdr),
                             addr, event.tgt_long.rlength, &rkey);
}

/*
 * Report what can be of \a stream, in order: the entry at the head of its
 * chain if ready, then the next, until one is not. Other streams do not wait.
 *
 * A report can call into UCP, which may re-enter progress and bring events for
 * this stream: while busy the stream is not advanced or given back; this loop
 * picks up what they did.
 */
static void uct_cxi_unexp_advance(uct_cxi_iface_t *iface,
                                  uct_cxi_unexp_stream_t *stream)
{
    uct_cxi_unexp_report_t *e;

    if (stream->busy) {
        return;
    }

    stream->busy = 1;
    while (((e = uct_cxi_unexp_head(stream)) != NULL) &&
           uct_cxi_unexp_is_ready(e)) {
        uct_cxi_unexp_unlink(iface, e);
        uct_cxi_unexp_report(iface, e);
    }
    stream->busy = 0;
    uct_cxi_unexp_stream_put(iface, stream);
}

/* An address read is over. */
static void uct_cxi_unexp_read_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_unexp_report_t *e = (uct_cxi_unexp_report_t *)op;

    e->state = (status == UCS_OK) ? UCT_CXI_UNEXP_READY :
                                    UCT_CXI_UNEXP_FAILED;
    ucs_assert(!(e->flags & UCT_CXI_UNEXP_LOST));
    uct_cxi_unexp_advance(e->iface, e->stream);
}

/* The announce of \a initiator has been seen: post the address reads of its
 * rendezvous that waited for it. The wait list is rescanned after each, as a
 * failed read is reported, which can call into UCP. */
static void uct_cxi_unexp_announced(uct_cxi_iface_t *iface, uint32_t initiator)
{
    uct_cxi_unexp_report_t *e;

    for (;;) {
        ucs_list_for_each(e, &iface->tag.unexp_wait, wait) {
            if (e->initiator == initiator) {
                break;
            }
        }
        if (&e->wait == &iface->tag.unexp_wait) {
            return;
        }

        ucs_list_del(&e->wait);
        ucs_list_head_init(&e->wait);
        uct_cxi_unexp_start(iface, e);
        if (e->state == UCT_CXI_UNEXP_FAILED) {
            uct_cxi_unexp_advance(iface, e->stream);
        }
    }
}

/*
 * The delayed match of message \a event (a rendezvous, or an eager message
 * without data, which have nothing to wait the arrival for) came before the
 * message was seen: the receive has it. Leave a tombstone for the arrival to
 * find; \a flags are added to UCT_CXI_UNEXP_LOST.
 */
static void uct_cxi_unexp_tombstone(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint8_t flags)
{
    ucs_debug("cxi TAG [UNEXP-LOST-FIRST] tag=0x%lx id=%u: claimed before it "
              "was seen arriving", (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rendezvous_id);
    if (ucs_unlikely(uct_cxi_unexp_alloc(iface, event,
                                         event->tgt_long.rendezvous,
                                         UCT_CXI_UNEXP_LOST | flags,
                                         iface->tag.unexp_seq++) == NULL)) {
        ucs_error("cxi TAG no free entry to note a message claimed by a "
                  "receive, tag=0x%lx initiator=0x%x",
                  (unsigned long)event->tgt_long.match_bits,
                  (unsigned)event->tgt_long.initiator.initiator.process);
    }
}

/*
 * The arrival of a rendezvous or an eager message without data is handled. If
 * its receive's match came first there is a tombstone: the message is that
 * receive's and nothing more is done (unless it goes to UCP after all, see
 * UCT_CXI_UNEXP_REDELIVER, which is reported now). Returns 1 if there was one.
 */
static int uct_cxi_unexp_arrival_lost(uct_cxi_iface_t *iface,
                                      const union c_event *event, uint64_t seq)
{
    uct_cxi_unexp_stream_t *stream =
            uct_cxi_unexp_stream_find(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);
    uint8_t                 is_rndv = event->tgt_long.rendezvous;
    uint8_t                 id      = event->tgt_long.rendezvous_id;
    uct_cxi_unexp_report_t *e;
    int                     redeliver;
    union c_event           copy;

    if ((stream == NULL) || (stream->num_lost == 0)) {
        return 0; /* no tombstone */
    }

    ucs_list_for_each(e, &stream->entries, link) {
        if ((e->flags & UCT_CXI_UNEXP_LOST) && (e->is_rndv == is_rndv) &&
            (!is_rndv || (e->rendezvous_id == id))) {
            break;
        }
    }
    if (&e->link == &stream->entries) {
        return 0;
    }

    redeliver = e->flags & UCT_CXI_UNEXP_REDELIVER;
    uct_cxi_unexp_discard(iface, e); /* the tombstone */
    if (redeliver) {
        copy = *event; /* the report may re-enter progress */
        uct_cxi_tag_found_eager(iface, &copy, seq);
    }
    uct_cxi_unexp_advance(iface, stream);
    return 1;
}

/* -------------------------------------------------------------------------
 * Pairing the two events of an unexpected eager message
 * -------------------------------------------------------------------------
 */

static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
                                             const union c_event *event,
                                             uint64_t seq);

/*
 * A delayed match of an eager message with data is about to be handled: it
 * copies from the overflow buffer, so it may only proceed once the message's
 * arrival has been seen (the Put is written after the data; see
 * uct_cxi_eager_pair_t). Returns 1 if it has, with the arrival number in
 * *seq_p. If not, the event is kept for uct_cxi_eager_take_parked() and 0 is
 * returned.
 */
static int uct_cxi_eager_match_ready(uct_cxi_iface_t *iface,
                                     const union c_event *event,
                                     uint64_t *seq_p)
{
    uct_cxi_eager_pair_t *pair;
    khiter_t              k;
    int                   ret;

    k = kh_get(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start);
    if (k != kh_end(&iface->tag.eager_pairs)) {
        pair = &kh_value(&iface->tag.eager_pairs, k);
        if (ucs_likely(!pair->parked)) {
            *seq_p = pair->seq;
            kh_del(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs, k);
            return 1;
        }
        ucs_error("cxi TAG a second match for the unexpected eager message "
                  "at 0x%lx", (unsigned long)event->tgt_long.start);
        return 0;
    }

    k = kh_put(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start, &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi TAG cannot wait for the arrival of the unexpected "
                  "eager message at 0x%lx: out of memory",
                  (unsigned long)event->tgt_long.start);
        *seq_p = iface->tag.unexp_seq++;
        return 1;
    }

    pair         = &kh_value(&iface->tag.eager_pairs, k);
    pair->parked = 1;
    pair->event  = *event;
    ucs_debug("cxi TAG [EAGER-MATCH-EARLY] start=0x%lx delayed match before "
              "its arrival", (unsigned long)event->tgt_long.start);
    return 0;
}

/*
 * The arrival of an unexpected eager message with data is being handled. If its
 * receive's match came first, carry on with it now and return 1: the message is
 * that receive's. Otherwise return 0, keeping nothing.
 */
static int uct_cxi_eager_take_parked(uct_cxi_iface_t *iface,
                                     const union c_event *event, uint64_t seq)
{
    uct_cxi_eager_pair_t pair;
    khiter_t             k;

    k = kh_get(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start);
    if (k == kh_end(&iface->tag.eager_pairs)) {
        return 0;
    }

    pair = kh_value(&iface->tag.eager_pairs, k);
    if (!pair.parked) {
        ucs_error("cxi TAG a second arrival of the unexpected eager message "
                  "at 0x%lx", (unsigned long)event->tgt_long.start);
        return 0;
    }

    kh_del(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs, k);

    /* The handler may call into UCP; nothing of ours is referenced after. */
    uct_cxi_tag_eager_match_complete(iface, &pair.event, seq);
    return 1;
}

/* The arrival of an unexpected eager message with data that a receive was
 * claimed for is handled: note it for the receive's match. */
static void uct_cxi_eager_note(uct_cxi_iface_t *iface,
                               const union c_event *event, uint64_t seq)
{
    khiter_t k;
    int      ret;

    k = kh_put(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start, &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi TAG cannot note the arrival of the unexpected eager "
                  "message at 0x%lx: out of memory",
                  (unsigned long)event->tgt_long.start);
        return;
    }

    kh_value(&iface->tag.eager_pairs, k).parked = 0;
    kh_value(&iface->tag.eager_pairs, k).seq    = seq;
}

/*
 * Report an unexpected eager message (arrival number \a seq) to UCP at once,
 * unless an earlier unexpected message with the same tag from the same sender
 * is still held (a rendezvous waiting for its address): UCP must hear of that
 * first, so this waits behind it. One load when no rendezvous is held.
 */
static void uct_cxi_tag_found_eager(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint64_t seq)
{
    if (ucs_unlikely(iface->tag.unexp_held != 0) &&
        (cxi_event_rc(event) == C_RC_OK)) {
        uct_cxi_unexp_stream_t *stream =
                uct_cxi_unexp_stream_find(
                        iface, event->tgt_long.initiator.initiator.process,
                        event->tgt_long.match_bits);

        if ((stream != NULL) && uct_cxi_unexp_has_older(stream, seq)) {
            if (uct_cxi_unexp_alloc(iface, event, 0, 0, seq) != NULL) {
                return;
            }
            ucs_warn("cxi TAG no free entry to hold an unexpected eager "
                     "message behind an unexpected rendezvous: reporting it "
                     "out of order");
        }
    }

    uct_cxi_iface_tag_report_unexp_eager(iface, event);
}

/*
 * The outcome of a SEARCH_AND_DELETE that found and deleted a message
 * (C_EVENT_PUT_OVERFLOW with UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID). Nothing to
 * do: the message was handed to UCP on arrival (the command only removes it
 * from the NIC's list), and its reference and credits go back when it is
 * reported. The one found is the oldest with the tag, which is the one the
 * command was issued for: every older one was taken by an earlier receive or
 * command.
 */
void uct_cxi_iface_tag_handle_search_delete_found(uct_cxi_iface_t *iface,
                                                  const union c_event *event)
{
    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        ucs_error("cxi TAG [SEARCH-DELETE-UNEXPECTED-RC] tag=0x%lx rc=%d",
                  (unsigned long)event->tgt_long.match_bits,
                  cxi_event_rc(event));
        return;
    }

    ucs_debug("cxi TAG [SEARCH-DELETE-FOUND] tag=0x%lx rlength=%u rndv=%u",
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rlength,
              (unsigned)event->tgt_long.rendezvous);
}

/*
 * A SEARCH_AND_DELETE found nothing: a receive appended before it took the
 * message. That receive was in the ring when the arrival was handled and would
 * have been claimed, so the ring is wrong and UCP was given a message a receive
 * also has.
 */
void uct_cxi_iface_tag_handle_search_delete_missed(uct_cxi_iface_t *iface,
                                                   const union c_event *event)
{
    ucs_error("cxi TAG [SEARCH-DELETE-NOT-FOUND] rc=%d: a message handed to "
              "UCP was taken by a posted receive as well",
              cxi_event_rc(event));
}

/*
 * Handler for the announce sent by uct_cxi_ep_send_rndv_hdr_announce(),
 * dispatched before uct_iface_invoke_am() (it is not a user AM). Fills
 * iface->tag.rndv_peer_cache for this initiator, then lets its waiting
 * unexpected rendezvous go on.
 */
void uct_cxi_iface_handle_rndv_hdr_announce(uct_cxi_iface_t *iface,
                                            const union c_event *event,
                                            const void *payload, uint32_t len)
{
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    const uct_cxi_rndv_peer_hdr_t *hdr = payload;
    khiter_t k;
    int      ret;

    if (ucs_unlikely(len != sizeof(*hdr))) {
        ucs_error("cxi TAG [RNDV-HDR-ANNOUNCE] bad length %u, expected %zu",
                 len, sizeof(*hdr));
        return;
    }

    k = kh_put(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache, initiator,
              &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi TAG [RNDV-HDR-ANNOUNCE] rndv_peer_cache insert "
                 "failed, initiator=0x%x", initiator);
        return;
    }
    kh_value(&iface->tag.rndv_peer_cache, k) = *hdr;

    ucs_debug("cxi TAG [RNDV-HDR-ANNOUNCE] initiator=0x%x ep_id=0x%lx "
             "md_index=%u table_iova=0x%lx", initiator,
             (unsigned long)hdr->ep_id, (unsigned)hdr->md_index,
             (unsigned long)hdr->table_iova);

    uct_cxi_unexp_announced(iface, initiator);
}

/*
 * A Put the NIC could not place in an overflow buffer. The event reports the
 * failure and carries no message: nothing to look for, hand on, protect or give
 * back (the sender sees the failure in its ACK and takes its credits back). The
 * usual cause is a message longer than what is left of its buffer, which is not
 * tried on the next; min_free is the largest message to prevent that.
 */
static UCS_F_NOINLINE void
uct_cxi_iface_tag_ovf_failed(uct_cxi_iface_t *iface, const union c_event *event)
{
    int buf_idx = (int)event->tgt_long.buffer_id;

    ucs_error("cxi TAG overflow Put failed: rc=%d buf=%d tag=0x%lx "
              "rlength=%u mlength=%u, message dropped",
              (int)cxi_event_rc(event), buf_idx,
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rlength,
              (unsigned)event->tgt_long.mlength);

    /* The buffer's fate does not depend on how this Put went. */
    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        iface->tag.ovf_repost_pending[buf_idx] = 1;
        uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
    }
}

/*
 * An unexpected message landed in the overflow ring (C_EVENT_PUT, ptl_list ==
 * OVERFLOW). Takes a reference on the buffer generation if mlength > 0 (see
 * ovf_refcnt) and decides at once whose the message is. Arrivals are handled in
 * landing order, and one of three holds:
 *
 *   1. A receive's delayed match was seen first (parked for an eager message
 *      with data, a tombstone for the others): the message is that receive's.
 *   2. A receive appended after it landed will take it: the first of the ring
 *      (uct_cxi_tag_claim()) matching its tag. It is claimed, UCP told it is
 *      taken, and its delayed match completes it.
 *   3. Otherwise it is UCP's: a SEARCH_AND_DELETE takes it off the NIC's list
 *      so no later receive can take it, and it is reported at once. A receive
 *      UCP posts afterwards is matched to it by UCP, not offloaded.
 *
 * Reporting only after the command found the message left a window where UCP
 * matched an older receive to it while that receive had taken another message
 * in hardware (the tag_bw hang).
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    int      buf_idx  = (int)event->tgt_long.buffer_id;
    uint64_t tag      = event->tgt_long.match_bits;
    uint64_t seq      = iface->tag.unexp_seq++; /* the order of arrivals */
    int      is_rndv  = event->tgt_long.rendezvous;
    int      has_data = (event->tgt_long.mlength > 0);
    uct_cxi_unexp_report_t *e = NULL;
    struct c_target_cmd sd = {};
    ucs_status_t status;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        uct_cxi_iface_tag_ovf_failed(iface, event);
        return;
    }

    if (has_data) {
        iface->tag.ovf_refcnt[buf_idx]++;
        /* Checked here too, not just from uct_cxi_iface_tag_ovf_release() --
         * see uct_cxi_iface_tag_ovf_maybe_repost()'s own doc comment for why
         * this side needs it as well. */
        uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
    }
    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        /* EQ delivery is ordered, so this is the generation's last Put: record
         * that a repost is owed once every message in it is resolved. Not yet:
         * an earlier unresolved message would have its memory reused. */
        iface->tag.ovf_repost_pending[buf_idx] = 1;
    }

    ucs_info("cxi TAG [OVF-ARRIVAL] buf_idx=%d tag=0x%lx mlength=%u "
             "rlength=%u start=0x%lx auto_unlinked=%u", buf_idx,
             (unsigned long)tag, (unsigned)event->tgt_long.mlength,
             (unsigned)event->tgt_long.rlength,
             (unsigned long)event->tgt_long.start,
             (unsigned)event->tgt_long.auto_unlinked);

    /* 1. The match came first. */
    if (has_data && !is_rndv) {
        if (uct_cxi_eager_take_parked(iface, event, seq)) {
            return;
        }
    } else if (uct_cxi_unexp_arrival_lost(iface, event, seq)) {
        return;
    }

    /* 2. A receive is to take it. Its sender's charge for the event slots of a
     * rendezvous goes back now, nothing of it is held; an eager message's
     * goes back with its buffer, when the receive's match has copied it. */
    if (uct_cxi_tag_claim(iface, tag)) {
        if (is_rndv) {
            uct_cxi_tag_credit_return(
                    iface, event->tgt_long.initiator.initiator.process,
                    UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
        } else if (has_data) {
            uct_cxi_eager_note(iface, event, seq);
        }
        return;
    }

    /* 3. It is UCP's. A rendezvous is held for the read of its source address,
     * an eager message reported on the spot. The entry is taken first: with
     * none, the message stays in the NIC's list, for a receive to take. */
    if (is_rndv) {
        e = uct_cxi_unexp_alloc(iface, event, 1, 0, seq);
        if (ucs_unlikely(e == NULL)) {
            ucs_error("cxi TAG no free entry to hold an unexpected "
                      "rendezvous, tag=0x%lx initiator=0x%x -- not reported "
                      "unless a receive claims it", (unsigned long)tag,
                      (unsigned)event->tgt_long.initiator.initiator.process);
            return;
        }
    }

    /* Targets C_PTL_LIST_UNEXPECTED (as every libfabric SEARCH call), not
     * OVERFLOW. match_id must be CXI_MATCH_ID_ANY to be a wildcard, and length
     * must be set (zero is an empty region and gave C_RC_NO_SPACE), as in
     * libfabric's SEARCH_AND_DELETE sites. use_once=1 (as its
     * cxip_claim_ux_onload()) makes each command raise exactly one event:
     * C_EVENT_PUT_OVERFLOW (C_RC_OK) if it deleted a message, C_EVENT_SEARCH
     * (C_RC_NO_MATCH) if not. buffer_id UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID
     * only marks the event as its outcome. */
    sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
    sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    sd.ptlte_index    = iface->tag.ptn;
    sd.match_bits     = tag;
    sd.ignore_bits    = 0;
    sd.match_id       = CXI_MATCH_ID_ANY;
    sd.length         = -1U;
    sd.use_once       = 1;
    sd.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID;

    /* uct_cxi_iface_tgt_post() waits out a full command queue. If it stays
     * wedged, the message is not handed to UCP: it stays on the NIC's list for
     * whatever claims it later, which also gets its buffer reference and
     * credits. */
    status = uct_cxi_iface_tgt_post(iface, &sd);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi TAG SEARCH_AND_DELETE post failed: %s -- unexpected "
                  "message tag=0x%lx is not reported unless a receive claims "
                  "it", ucs_status_string(status), (unsigned long)tag);
        if (is_rndv) {
            uct_cxi_unexp_stream_t *stream = e->stream;

            uct_cxi_unexp_discard(iface, e);
            uct_cxi_unexp_advance(iface, stream);
        } else if (has_data) {
            uct_cxi_eager_note(iface, event, seq);
        }
        return;
    }

    if (is_rndv) {
        /* What waited for the address read can go on if it was not posted. */
        uct_cxi_unexp_start(iface, e);
        uct_cxi_unexp_advance(iface, e->stream);
    } else {
        uct_cxi_tag_found_eager(iface, event, seq);
    }
}

/*
 * Software-issued (get_issued==0) pull for a direct-matched rendezvous receive:
 * an unrestricted (matching-mode) DMA Get to the sender's rendezvous source PTE
 * at the device's rdzv_get_idx (restricted does not work, see
 * uct_cxi_rdzv_op_t). The sender's DFA comes from the event's initiator (tag
 * receives have no ep; cxi_dfa_nid/pid, as libfabric).
 *
 * cmd.match_bits carries the sender's rendezvous id from
 * event->tgt_long.rendezvous_id, which the sender reads back off its
 * C_EVENT_GET. local_addr is the destination buffer (event->tgt_long.start):
 * the full [0, rlength) is fetched, since a rendezvous Put never
 * eager-attaches. user_ptr is a uct_cxi_rdzv_get_op_t (op first), so the REPLY
 * completes through op->handler (uct_cxi_rdzv_get_comp).
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
    /* pid_idx must be the sender's rdzv_get_idx, as for the NIC's own Get (see
     * uct_cxi_iface_open_rdzv_pte). */
    cxi_build_dfa(sender_nid, sender_pid, md->pid_bits,
                 md->cxi_dev->info.rdzv_get_idx, &dfa, &idx_ext);

    /* Always fetches the full [0, rlength) range -- a rendezvous Put never
     * eager-attaches anything on this transport (see uct_ep_tag_rndv_
     * zcopy), so there is never a prefix to skip past. */
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
        cmd.lac                = 0; /* LAC 0 only */
        cmd.event_send_disable = 1;
        cmd.restricted         = 0;
        cmd.initiator          = iface->match_id;
        /* REPLY on the RX queue, where a NIC-issued Get's lands too: a handler
         * cannot be refused for a full TX queue, and each posted receive has a
         * slot budgeted for one Get REPLY. */
        cmd.eq                 = iface->rx_eq.evtq->eqn;
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
 * The slot/ctx lookup shared by the tag match handlers. The caller classifies
 * eager vs rendezvous (event->tgt_long.rendezvous); SEARCH_AND_DELETE outcomes
 * are routed before this. Returns the matched ctx with *slot_p set, or NULL for
 * a stale or already-resolved slot.
 */
static uct_tag_context_t *
uct_cxi_iface_tag_match_lookup(uct_cxi_iface_t *iface,
                               const union c_event *event, int *slot_p)
{
    int slot = (int)event->tgt_long.buffer_id;

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale event for a resolved slot, e.g. UCP force-cancelled the receive
         * after the hardware's search-on-append raced our SEARCH_AND_DELETE.
         * Safe to drop. */
        ucs_debug("cxi TAG [MATCH-STALE] slot=%d already resolved, "
                 "dropping", slot);
        return NULL;
    }

    *slot_p = slot;
    return iface->tag.ctx[slot];
}

/*
 * The receive a delayed match is for is gone (UCP assumed its cancel successful
 * and matched its message elsewhere), yet it took the message. UCP has not been
 * told of the message: report it now as unexpected. An eager message with data
 * is whole in the ring (\a seq numbers its seen arrival); one without has its
 * arrival to come, for which a tombstone is left.
 */
static void uct_cxi_tag_match_orphan(uct_cxi_iface_t *iface,
                                     const union c_event *event, uint64_t seq)
{
    union c_event copy;

    if (event->tgt_long.rlength == 0) {
        uct_cxi_unexp_tombstone(iface, event, UCT_CXI_UNEXP_REDELIVER);
        return;
    }

    ucs_info("cxi TAG [MATCH-REDELIVER] tag=0x%lx rlength=%u: the receive was "
             "cancelled, reporting the message it took",
             (unsigned long)event->tgt_long.match_bits,
             (unsigned)event->tgt_long.rlength);
    copy                    = *event;
    copy.tgt_long.mlength   = event->tgt_long.rlength; /* all of it is in the ring */
    uct_cxi_tag_found_eager(iface, &copy, seq);
}

/*
 * A plain eager match, direct (C_EVENT_PUT, PRIORITY) or delayed
 * (C_EVENT_PUT_OVERFLOW); never a rendezvous-flagged event.
 *
 * Direct: the data was DMAed into the caller's buffer (inline_data stays NULL).
 * Delayed: the data landed in the overflow ring before this LE existed and
 * Portals4 never re-targets it, so copy it into priv->recv_addr here (as
 * libfabric's cxip_ux_send()), then release the overflow reference and return
 * the sender's credits. \a seq is the arrival number (see
 * uct_cxi_iface_tag_handle_eager_match()); it matters only if the receive is
 * gone.
 *
 * tag_consumed_cb is called here unless the arrival already did
 * (uct_cxi_tag_claim()); the slot's PENDING state in the ring ends either way.
 *
 * Checks cancel_ctx[slot].force before touching ctx/priv (see cancel_ctx): if
 * set, UCP may have recycled them, so the slot is reclaimed without reading ctx
 * and the message the receive took is reported to UCP as unexpected
 * (uct_cxi_tag_match_orphan()); dropping it was the tag_bw hang.
 */
static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
                                             const union c_event *event,
                                             uint64_t seq)
{
    int                      slot;
    uct_tag_context_t      *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t                 stag;
    uint64_t                 imm;
    uint32_t                 mlength;
    ucs_status_t             status;
    int                      buf_idx;
    unsigned                 prev = UCT_CXI_TAG_PEND_FREE;

    int                      delayed = (event->hdr.event_type ==
                                        C_EVENT_PUT_OVERFLOW);
    int                      has_data  = (event->tgt_long.rlength > 0);
    uint32_t                 initiator = event->tgt_long.initiator.initiator.
                                         process;
    uint32_t                 sent_len  = event->tgt_long.rlength;

    if ((unsigned)event->tgt_long.buffer_id < iface->tag.max_outstanding) {
        prev = uct_cxi_tag_pend_spent(iface, event->tgt_long.buffer_id);
    }

    ctx = uct_cxi_iface_tag_match_lookup(iface, event, &slot);
    if (ctx == NULL) {
        /* The receive is gone, but the message it matched is still ours to be
         * done with. */
        if (delayed) {
            uct_cxi_tag_match_orphan(iface, event, seq);
        }
        return;
    }

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        /* Force-cancelled: ctx is never read on this branch. */
        iface->tag.cancel_ctx[slot].force = 0;
        if (delayed) {
            uct_cxi_tag_match_orphan(iface, event, seq);
        }
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;

    ucs_info("cxi EAGER TAG [%s] slot=%d tag=0x%lx mlength=%u",
             delayed ? "OVF-MATCHED" : "DIRECT-MATCH",
             slot, (unsigned long)event->tgt_long.match_bits,
             (unsigned)event->tgt_long.mlength);

    if (delayed) {
        /* Delayed match: copy out of the overflow buffer, then release it and
         * return the credits (uct_cxi_tag_ovf_done()). Gated on the message
         * having data, as the arrival's increment. */
        buf_idx = -1;
        if (has_data) {
            void *data;

            buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start);
            data    = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                 event->tgt_long.start);
            memcpy((void *)(uintptr_t)priv->recv_addr, data,
                   event->tgt_long.mlength);
        }
        uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);

        if (!has_data && (prev != UCT_CXI_TAG_PEND_CLAIMED)) {
            /* Nothing to wait the arrival by, and it was not seen, so it did
             * not find this receive: leave a note for it. */
            uct_cxi_unexp_tombstone(iface, event, 0);
        }
    }

    stag    = event->tgt_long.match_bits;
    imm     = event->tgt_long.header_data;
    mlength = event->tgt_long.mlength;
    status  = (event->tgt_long.rlength > mlength) ? UCS_ERR_MESSAGE_TRUNCATED :
                                                    UCS_OK;

    if (!(priv->rndv_flags & UCT_CXI_TAG_FLAG_CONSUMED)) {
        ctx->tag_consumed_cb(ctx);
    }

    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        /* A software rendezvous request: its payload, UCP's RTS, is in the
         * receive's buffer (put there by the NIC or the copy above); UCP
         * carries on from it. Truncated if the buffer was too small. */
        ctx->rndv_cb(ctx, stag, (const void *)(uintptr_t)priv->recv_addr,
                     mlength, status, 0);
        return;
    }

    ctx->completed_cb(ctx, stag, imm, mlength, NULL, status);
}

/*
 * See uct_cxi_tag_eager_match_complete(). A delayed match with data waits for
 * the message's arrival event (uct_cxi_eager_match_ready()): the match and the
 * arrival come from different NIC pipelines, so the match can be seen before
 * the payload is in the ring.
 */
void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    uint64_t seq = 0;

    if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
        (event->tgt_long.rlength > 0) &&
        !uct_cxi_eager_match_ready(iface, event, &seq)) {
        return; /* its arrival is yet to come: see uct_cxi_eager_take_parked() */
    }

    uct_cxi_tag_eager_match_complete(iface, event, seq);
}

/* OR seen_bit into a force-cancelled slot's cancel_ctx state and reclaim it
 * once UCT_CXI_RNDV_SEEN_REQUIRED is satisfied: other events of the transfer
 * may still be in flight (see cancel_ctx). */
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

/* Fail a rendezvous receive now and leave its slot to the cancel_ctx deferred
 * reclaim, as if force-cancelled: other required events (an independent Get, a
 * Put or Rendezvous not yet arrived) must drain before the slot is reused. Used
 * for Get issue and completion failures. */
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
 * A rendezvous match: C_EVENT_PUT/PUT_OVERFLOW with rendezvous == 1, or
 * C_EVENT_RENDEZVOUS itself (announces the pull). The receive completes once
 * all of UCT_CXI_RNDV_SEEN_REQUIRED has arrived; Put and Rendezvous come in
 * either order (as libfabric's rdzv_recv_req_event()), Reply only after
 * C_EVENT_RENDEZVOUS was processed. tag_consumed_cb fires on the first event:
 * it only means "don't also match this in software".
 *
 * Checks cancel_ctx[slot].force before touching ctx/priv; a force-cancelled
 * slot accumulates via uct_cxi_iface_tag_rdzv_cancel_seen() until reclaimed.
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

    if ((event->hdr.event_type != C_EVENT_RENDEZVOUS) &&
        ((unsigned)event->tgt_long.buffer_id < iface->tag.max_outstanding)) {
        unsigned prev = uct_cxi_tag_pend_spent(iface, event->tgt_long.buffer_id);

        if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
            (prev != UCT_CXI_TAG_PEND_CLAIMED)) {
            /* The delayed match of a rendezvous that arrived unexpected
             * came first, whether or not the receive is still there: leave
             * a note for the arrival, which this message is not UCP's by. */
            uct_cxi_unexp_tombstone(iface, event, 0);
        }
    }

    if (ctx == NULL) {
        return;
    }

    seen_bit = (event->hdr.event_type == C_EVENT_RENDEZVOUS) ?
            UCT_CXI_RNDV_SEEN_RNDV : UCT_CXI_RNDV_SEEN_PUT;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
            /* The buffer is gone (UCP's contract for force=1): never issue a
             * Get into it. The pull's Reply is abandoned if no Get was issued
             * (get_issued==0), but kept pending if the NIC's auto-Get is in
             * flight: it completes via uct_cxi_iface_tag_handle_rdzv_reply(),
             * back through this accumulation. */
            ucs_debug("cxi TAG [RNDV-CANCEL] slot=%d get_issued=%u", slot,
                     (unsigned)event->tgt_long.get_issued);
            if (!event->tgt_long.get_issued) {
                iface->tag.cancel_ctx[slot].rndv_seen |= UCT_CXI_RNDV_SEEN_REPLY;
            }
        }
        /* Put/Put_Overflow needs no release here -- mlength is always 0 for
         * a rendezvous arrival (see uct_ep_tag_rndv_zcopy), so no
         * ovf_refcnt reference was ever taken for it. */
        uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
               priv->slot, slot);

    if (!(priv->rndv_flags & UCT_CXI_RNDV_FLAG_IS_RNDV)) {
        /* First of the three events: fire tag_consumed_cb now (it only concerns
         * software double-matching), unless the arrival already did
         * (uct_cxi_tag_claim()). */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_IS_RNDV;
        if (!(priv->rndv_flags & UCT_CXI_TAG_FLAG_CONSUMED)) {
            ctx->tag_consumed_cb(ctx);
        }
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
        /* match_bits is the real tag only on PUT/PUT_OVERFLOW: on
         * C_EVENT_RENDEZVOUS it is hardware bookkeeping (its low 8 bits are the
         * sender's rdzv id). Capturing it there would corrupt the tag when
         * RENDEZVOUS is processed after the Put-side event; order is not
         * guaranteed. */
        priv->stag = event->tgt_long.match_bits;
    }
    priv->length      = event->tgt_long.rlength;
    priv->rndv_flags |= seen_bit;
    if (event->tgt_long.rlength > priv->posted_len) {
        /* Truncation is against the posted buffer's capacity: mlength is always
         * 0 for a rendezvous arrival, so rlength > mlength is true for nearly
         * any message (see posted_len). */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_TRUNCATED;
    }

    if ((event->hdr.event_type == C_EVENT_RENDEZVOUS) &&
        ucs_unlikely(!event->tgt_long.get_issued)) {
        status = uct_cxi_iface_issue_rdzv_get(iface, event, (uint16_t)slot,
                                            priv->posted_len);
        if (ucs_unlikely(status != UCS_OK)) {
            /* Resource exhaustion issuing the pull -- fail now (no Get
             * means no Reply will ever arrive) and defer slot reclaim,
             * since the Put/Put_Overflow event may still be pending. */
            ucs_error("cxi TAG failed to issue rdzv Get, slot=%d", slot);
            uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot,
                                       UCT_CXI_RNDV_SEEN_REPLY, status);
            return;
        }
        /* SEEN_REPLY arrives later via uct_cxi_rdzv_get_comp() once this
         * Get's own C_EVENT_REPLY lands. */
    }
    /* get_issued==1 (common): the NIC's own pull covers the whole message and
     * its C_EVENT_REPLY marks SEEN_REPLY via
     * uct_cxi_iface_tag_handle_rdzv_reply(). Nothing to do here; the Put events
     * need nothing either (mlength is 0: no header, no overflow reference). */

    if ((priv->rndv_flags & UCT_CXI_RNDV_SEEN_REQUIRED) !=
        UCT_CXI_RNDV_SEEN_REQUIRED) {
        return; /* Still waiting for another required event. */
    }

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    stag   = priv->stag;
    /* Cap the delivered length at the posted capacity on truncation, as the
     * eager path; otherwise priv->length never exceeds posted_len. */
    length = ucs_min(priv->length, priv->posted_len);
    /* A failed Get completes immediately via uct_cxi_iface_tag_rdzv_fail()
     * instead of reaching here, so only truncation is left to check. */
    status = (priv->rndv_flags & UCT_CXI_RNDV_FLAG_TRUNCATED) ?
            UCS_ERR_MESSAGE_TRUNCATED : UCS_OK;

    /* imm is always 0 for rendezvous per uct_ep_tag_rndv_zcopy's own doc.
     * inline_data is always NULL, same reason as the eager handler. */
    ctx->completed_cb(ctx, stag, 0, length, NULL, status);
}

/* Completion of a rendezvous receive's pull Get (SEEN_REPLY, via
 * uct_cxi_iface_tag_handle_rdzv_reply or uct_cxi_rdzv_get_comp): mark it and
 * fire completed_cb once UCT_CXI_RNDV_SEEN_REQUIRED is satisfied. */
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
        /* Stale event for a resolved slot, e.g. UCP force-cancelled the receive
         * after the hardware's search-on-append raced our SEARCH_AND_DELETE.
         * Safe to drop. */
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
        /* Fail now rather than accumulate: a failed pull has no partial
         * success, and this reports the status once without merging it with a
         * second outstanding Get. */
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

/* C_EVENT_REPLY of a NIC auto-issued (get_issued==1) rendezvous Get. Its
 * user_ptr is a bit-packed struct cxi_rdzv_user_ptr (cxi_prov_hw.h) whose
 * buffer_id is the priority-LE slot, so no lookup table is needed. Called
 * before the generic REPLY handling, which would cast it to a send op. */
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

/* uct_cxi_send_op_t::handler for a software-issued rendezvous Get's REPLY,
 * dispatched through the generic path (we built its user_ptr). */
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
 * C_EVENT_UNLINK on the tag PTE. The priority-LE APPEND sets
 * event_unlink_disable (as libfabric), so the automatic use_once unlink raises
 * none and tag_handle_match() cleans up its slot. What reaches here:
 *   - a tag_recv_cancel() UNLINK that lost to a match (ENTRY_NOT_FOUND): drop;
 *   - a manual unlink of an overflow buffer at teardown (OVERFLOW): nothing to
 *     repost;
 *   - a genuine cancel confirmation (PRIORITY, C_RC_OK): the case this exists
 *     for, since every priority-list UNLINK here is one.
 * A winning UNLINK means the LE was removed before any match, a terminal
 * disposition for eager or rendezvous alike, so a force-cancelled slot is
 * reclaimed at once with no rndv_seen accumulation (contrast
 * tag_handle_rdzv_match()). Checks cancel_ctx[slot].force before touching
 * ctx/priv.
 */
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    int                     slot;
    uct_tag_context_t      *ctx;

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
    ucs_assertv(((uct_cxi_tag_ctx_priv_t *)ctx->priv)->slot == (uint16_t)slot,
               "priv->slot=%u slot=%d",
               ((uct_cxi_tag_ctx_priv_t *)ctx->priv)->slot, slot);

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

/* The unrestricted IDC tag send (up to 192 B) of an eager message with only
 * \a imm out of band, and of a software rendezvous request (imm
 * UCT_CXI_TAG_SW_RNDV_IMM): the same message meaning something else to the
 * receiver, charged and returned as eager tag traffic. */
static ucs_status_t
uct_cxi_tag_short_send(uct_cxi_ep_t *ep, uct_tag_t tag, uint64_t imm,
                       const void *data, size_t length, const char *what)
{
    uct_cxi_iface_t *iface = uct_cxi_tag_ep_iface(ep);
    unsigned         units = UCT_CXI_FC_UNITS(length);
    ucs_status_t     status;
    int              credited;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_UNR, what);

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG,
                                UCT_CXI_FC_SLOTS_TAG_EAGER, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_tag, ep->dfa_tag_idx_ext,
                                 tag, imm, data, length, UCT_CXI_FC_TAG, units,
                                 credited, what);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);

    ucs_debug("cxi TAG [SEND-SHORT] ep=%p tag=0x%lx len=%zu imm=0x%lx", ep,
              (unsigned long)tag, length, (unsigned long)imm);
    return UCS_OK;
}

/* Unrestricted IDC tag send (up to 192 B), with no header reservation unlike
 * AM: imm travels in header_data, and eager_short has no imm (0; use bcopy for
 * non-zero). */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
    return uct_cxi_tag_short_send(ucs_derived_of(tl_ep, uct_cxi_ep_t), tag, 0,
                                  data, length, "tag_eager_short");
}

/* Unrestricted DMA tag send via a bounce buffer from the shared desc_pool. */
ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                    uint64_t imm, uct_pack_callback_t pack_cb,
                                    void *arg, unsigned flags)
{
    uct_cxi_ep_t         *ep    = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface = uct_cxi_tag_ep_iface(ep);
    uct_cxi_send_desc_t  *desc;
    size_t                length;
    unsigned              units;
    ucs_status_t          status;
    int                   credited;
    int                   ret;

    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        return UCS_ERR_INVALID_PARAM; /* the mark of a rendezvous request */
    }

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    /* As for an Active Message: the length is only known once it is packed,
     * which must happen once, so ask for one unit now and charge the real
     * cost afterwards. */
    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG,
                                UCT_CXI_FC_SLOTS_TAG_EAGER, 1, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return (ssize_t)status;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    length = pack_cb(desc + 1, arg);
    ucs_assertv(length <= iface->tag.max_msg, "length=%zu max_msg=%zu", length,
                iface->tag.max_msg);
    units  = UCT_CXI_FC_UNITS(length);

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
        cmd.initiator              = iface->match_id;
        cmd.eq                     = iface->tx_eq.evtq->eqn;
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
        uct_cxi_tx_emit_error(ep, "tag_eager_bcopy", ret);
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);
    uct_cxi_op_fc_set(&desc->op, credited, UCT_CXI_FC_TAG,
                      UCT_CXI_FC_SLOTS_TAG_EAGER, units);
    ucs_debug("cxi TAG [SEND-BCOPY] ep=%p tag=0x%lx imm=0x%lx len=%zu", ep,
             (unsigned long)tag, (unsigned long)imm, length);
    return (ssize_t)length;
}

/* Unrestricted DMA tag send from the caller's registered buffer. */
ucs_status_t uct_cxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_tag_ep_iface(ep);
    uct_cxi_mem_handle_t *memh   = (uct_cxi_mem_handle_t *)iov[0].memh;
    size_t                length = uct_iov_get_length(iov);
    unsigned              units  = UCT_CXI_FC_UNITS(length);
    uct_cxi_send_op_t    *op;
    ucs_status_t          status;
    int                   credited;
    int                   ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_eager_zcopy");

    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        return UCS_ERR_INVALID_PARAM; /* the mark of a rendezvous request */
    }
    UCT_CHECK_LENGTH(length, 0, iface->tag.max_msg, "tag_eager_zcopy");

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG,
                                UCT_CXI_FC_SLOTS_TAG_EAGER, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
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
        cmd.initiator              = iface->match_id;
        cmd.eq                     = iface->tx_eq.evtq->eqn;
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
        uct_cxi_tx_emit_error(ep, "tag_eager_zcopy", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);
    uct_cxi_op_fc_set(op, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                      units);
    ucs_debug("cxi TAG [SEND-ZCOPY] ep=%p tag=0x%lx imm=0x%lx len=%zu", ep,
             (unsigned long)tag, (unsigned long)imm, length);
    return UCS_INPROGRESS;
}


/* -------------------------------------------------------------------------
 * Rendezvous ops
 * -------------------------------------------------------------------------
 */

/*
 * Handler for a rendezvous Put's own local C_EVENT_ACK. C_CMD_RENDEZVOUS_PUT
 * raises it despite event_send_disable (as libfabric's
 * cxip_send_rdzv_put_cb() expects), and the generic dispatch casts its user_ptr
 * to a send op.
 *
 * On success this is not the completion of uct_ep_tag_rndv_zcopy's comp: that
 * fires when the peer's Get lands (uct_cxi_iface_tag_handle_rdzv_get), and both
 * sides of that pull propagate a failed rc themselves. So the op stays alive in
 * iface->rdzv.ops[]. On failure the Put never landed, no Get will come, and
 * nothing else would complete the op: free its id and fire comp with the error
 * (as libfabric's rdzv_send_req_complete()).
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
 * Expose \a iov for a native hardware pull. Targets ep->dfa_tag, the same PTE
 * as eager (C_CMD_RENDEZVOUS_PUT is a distinct opcode on the same matching
 * PTE). remote_offset is the iov's address, so the receiver's Get can address
 * into it on the rendezvous PTE. cmd.rendezvous_id carries this op's index in
 * iface->rdzv.ops[] to the receiver (see uct_cxi_rdzv_op_t).
 *
 * UCP passes the 17-byte offload rendezvous header on every call
 * (uct_cxi_rndv_hdr_wire_t). Only req_id varies and goes in cmd.header_data of
 * every Put (eager_length is always 0). ep_id and md_index are constant per ep
 * and travel once, lazily, in the announce (uct_cxi_ep_send_rndv_hdr_announce)
 * on this ep's first call; see iface->tag.rndv_peer_cache for the receive side.
 *
 * Returns &iface->rdzv.ops[id], tracked until the peer's Get lands or
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
    const uct_cxi_rndv_hdr_wire_t *hdr_w = header;
    uint64_t              local_addr;
    uint32_t              id;
    uct_cxi_rdzv_op_t    *rop;
    uint64_t              header_data;
    ucs_status_t          status;
    int                   credited;
    int                   ret;

    if (ucs_unlikely(iovcnt != 1ul)) {
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    /* Only req_id varies per send. header_length is always
     * sizeof(uct_cxi_rndv_hdr_wire_t) when this protocol is in use
     * (UCT_CXI_TAG_RNDV_MAX_HDR); guard anyway. */
    ucs_assert(header_length >= sizeof(*hdr_w));
    header_data = hdr_w->req_id;

    if (ucs_unlikely(!ep->rndv_hdr_announced)) {
        status = uct_cxi_ep_send_rndv_hdr_announce(ep, hdr_w->ep_id,
                                                   hdr_w->md_index);
        if (ucs_unlikely(status != UCS_OK)) {
            return UCS_STATUS_PTR(status); /* no id consumed yet -- caller
                                             * (UCP) will retry this send */
        }
        ep->rndv_hdr_announced = 1;
    }

    /* After the announce, which takes an event slot of its own. No buffer
     * space: a rendezvous message carries none of the data. */
    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG,
                                UCT_CXI_FC_SLOTS_TAG_RNDV, 0, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return UCS_STATUS_PTR(status);
    }

    if (ucs_unlikely(iface->rdzv.free_count == 0)) {
        return UCS_STATUS_PTR(UCS_ERR_EXCEEDS_LIMIT);
    }
    id  = iface->rdzv.free_ids[--iface->rdzv.free_count];
    rop = &iface->rdzv.ops[id];

    local_addr    = memh->iova_offset + (uint64_t)(uintptr_t)iov[0].buffer;

    /* Where a target that takes this off its unexpected list finds the source
     * address (iface->rdzv.addr_table). A plain store suffices: the Put is
     * written and the doorbell rung after it. */
    iface->rdzv.addr_table[id] = local_addr;

    rop->op.ep      = ep;   /* real ep: unlike uct_cxi_rdzv_get_op_t this op
                             * has an owning ep, so the generic ACK
                             * dispatch's outstanding/flush accounting
                             * applies (matching the increments below). */
    rop->op.comp    = NULL; /* unused -- rop's own `comp` below is the real
                             * completion, fired later once the peer's Get
                             * lands, not from this generic dispatch path */
    rop->op.handler = uct_cxi_rdzv_put_ack_comp;
    rop->comp     = comp;
    rop->length   = (uint32_t)length;
    rop->id       = (uint8_t)id;
    rop->valid    = 1;

    {
        struct c_full_dma_cmd cmd  = {};
        cmd.command.opcode         = C_CMD_RENDEZVOUS_PUT;
        cmd.index_ext              = ep->dfa_tag_idx_ext;
        cmd.lac                    = memh->cxi_md->lac;
        cmd.event_send_disable     = 1;
        cmd.restricted             = 0;
        cmd.initiator              = iface->match_id;
        cmd.eq                     = iface->tx_eq.evtq->eqn;
        cmd.dfa                    = ep->dfa_tag;
        cmd.match_bits             = tag;
        cmd.local_addr              = local_addr;
        cmd.request_len             = (uint32_t)length;
        cmd.remote_offset           = local_addr;
        cmd.eager_length            = 0;
        cmd.header_data             = header_data;
        cmd.use_offset_for_get      = 1;
        cmd.rendezvous_id           = (uint8_t)id; /* carried to the receiver
                                                    * in its RENDEZVOUS event */
        cmd.user_ptr                = (uint64_t)(uintptr_t)&rop->op;

        ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    }
    if (ucs_unlikely(ret != 0)) {
        rop->valid = 0;
        iface->rdzv.free_ids[iface->rdzv.free_count++] = id;
        uct_cxi_tx_emit_error(ep, "tag_rndv_zcopy", ret);
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_RNDV,
                     0);
    uct_cxi_op_fc_set(&rop->op, credited, UCT_CXI_FC_TAG,
                      UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
    ucs_debug("cxi TAG [RNDV-SEND] ep=%p tag=0x%lx id=%u local_addr=0x%lx "
             "len=%zu", ep, (unsigned long)tag, id,
             (unsigned long)local_addr, length);
    return rop;
}

/* Software-only removal. The op is removed only here or by
 * uct_cxi_iface_tag_handle_rdzv_get, and UCP never cancels a completed op (see
 * uct_cxi_rdzv_op_t). */
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
 * C_EVENT_GET on iface->rdzv.pte: a peer's Get read our exposed LE. match_bits
 * carries the op's id back (see uct_cxi_rdzv_op_t), for an O(1) lookup in
 * iface->rdzv.ops[]. Fires comp: the buffer is now reusable.
 *
 * Only the low 8 bits of match_bits are ours (the rdzv_id_lo width of
 * libfabric's union cxip_match_bits); hardware puts other bits above them, so
 * mask them off. This also bounds UCT_CXI_RDZV_MAX_OUTSTANDING_MAX at 256.
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

    if (rop->comp != NULL) {
        uct_invoke_completion(rop->comp, status);
    }
}

/*
 * A software rendezvous request: UCP's RTS (ucp_rndv_rts_hdr_t and the packed
 * key of the sender's buffer) as the payload of a tagged message, so it is
 * matched against the receiver's tag list in order with other tagged messages
 * and then handled by the receiver's UCP (the NIC moves no data). It is an
 * eager message but for its header_data (UCT_CXI_TAG_SW_RNDV_IMM): the same IDC
 * message, charged as eager tag traffic, which the receiver hands to rndv_cb
 * with no remote address instead of eager_cb or completed_cb (see
 * uct_cxi_tag_eager_match_complete() and
 * uct_cxi_iface_tag_report_unexp_eager()). As on InfiniBand nothing completes
 * it: UCS_OK when sent. UCP checks the request against the largest short
 * message.
 */
ucs_status_t uct_cxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length,
                                         unsigned flags)
{
    return uct_cxi_tag_short_send(ucs_derived_of(tl_ep, uct_cxi_ep_t), tag,
                                  UCT_CXI_TAG_SW_RNDV_IMM, header,
                                  header_length, "tag_rndv_request");
}


/* -------------------------------------------------------------------------
 * Receiver-side ops (priority-LE posting, the hot path)
 * -------------------------------------------------------------------------
 */

/*
 * Would a receive for \a tag and \a mask match a message UCP has yet to be told
 * of, held in a stream (a rendezvous waiting for its address, and what is
 * behind it)? That message is off the NIC's list, so a receive posted there
 * would take a later message, while UCP, told of the held one afterwards, would
 * match it to the oldest receive: this one. The receive is refused, so UCP
 * keeps it in software and matches it when the held message is reported. (Later
 * receives for the tag are offloaded in order by UCP through this function
 * again.) A stream with nothing left to report (a tombstone) does not count.
 * Walks the streams in use; one load of unexp_held is all the cost while no
 * rendezvous is held.
 */
static int uct_cxi_tag_held_matches(uct_cxi_iface_t *iface, uct_tag_t tag,
                                    uct_tag_t mask)
{
    uct_cxi_unexp_stream_t *stream;

    ucs_list_for_each(stream, &iface->tag.unexp_live, live) {
        if ((((tag ^ stream->tag) & mask) == 0) &&
            (uct_cxi_unexp_head(stream) != NULL)) {
            return 1;
        }
    }

    return 0;
}

ucs_status_t uct_cxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx)
{
    uct_cxi_iface_t        *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_mem_handle_t   *memh;
    uct_cxi_tag_ctx_priv_t *priv;
    uint16_t                slot;
    struct c_target_cmd     le    = iface->tag.recv_le;
    uct_cxi_tag_pend_t     *e;
    int                     ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_recv_zcopy");

    /* Exactly fills UCT_TAG_PRIV_LEN with recv_addr added -- catch it
     * here, not as a silent out-of-bounds write into
     * uct_tag_context_t::priv, if either grows again. */
    UCS_STATIC_ASSERT(sizeof(uct_cxi_tag_ctx_priv_t) <= UCT_TAG_PRIV_LEN);

    if (ucs_unlikely(iface->tag.free_count == 0)) {
        return UCS_ERR_EXCEEDS_LIMIT;
    }

    /* The ring of receives that can take an unexpected message is full: until
     * a fence returns, UCP is to match this one in software. */
    if (ucs_unlikely((iface->tag.pend_head - iface->tag.pend_tail) >=
                     UCT_CXI_TAG_PEND_SIZE)) {
        return UCS_ERR_NO_RESOURCE;
    }

    if (ucs_unlikely(iface->tag.unexp_held != 0) &&
        uct_cxi_tag_held_matches(iface, tag, tag_mask)) {
        ucs_debug("cxi TAG [PRI-LE-REFUSED] tag=0x%lx tag_mask=0x%lx: matches "
                  "an unexpected message held for UCP", (unsigned long)tag,
                  (unsigned long)tag_mask);
        return UCS_ERR_NO_RESOURCE;
    }

    memh = (uct_cxi_mem_handle_t *)iov[0].memh;
    slot = iface->tag.free_list[--iface->tag.free_count];

    priv                    = (uct_cxi_tag_ctx_priv_t *)ctx->priv;
    priv->slot              = slot;
    priv->rndv_flags        = 0;
    priv->posted_len        = (uint32_t)iov[0].length;
    priv->recv_addr         = (uint64_t)(uintptr_t)iov[0].buffer;
    iface->tag.ctx[slot] = ctx;

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
        uct_cxi_tx_emit_error(NULL, "tag_recv_zcopy priority LE append", ret);
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tgt.cmdq);

    /* It can take an unexpected message from now on. */
    iface->tag.slot_pos[slot] = iface->tag.pend_head;
    e                         = &iface->tag.pend[iface->tag.pend_head++ &
                                                 UCT_CXI_TAG_PEND_MASK];
    e->tag                    = tag;
    e->mask                   = tag_mask;
    e->slot                   = slot;
    e->state                  = UCT_CXI_TAG_PEND_PENDING;
    if (++iface->tag.fence_posts >= iface->tag.fence_interval) {
        uct_cxi_tag_fence_post(iface);
    }

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
    uint32_t                pos   = iface->tag.slot_pos[priv->slot];

    /* A message arriving from now on is not this receive's to take, whatever
     * becomes of the cancel: if hardware had given it one already, the match
     * comes after (UCP's to deal with, as for any cancel that is raced). */
    if (uct_cxi_tag_pend_in_window(iface, pos) &&
        (iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK].state ==
         UCT_CXI_TAG_PEND_PENDING)) {
        iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK].state =
                UCT_CXI_TAG_PEND_SPENT;
    }

    if (force) {
        /* priv is read here for the last time, synchronously, while ctx is
         * still our caller's valid request: with force=1 UCP assumes the cancel
         * done and may recycle ctx/priv at once. Snapshot the rendezvous
         * accumulation into iface-owned memory; neither ctx nor priv may be
         * touched for this slot from here on (see cancel_ctx). */
        iface->tag.cancel_ctx[priv->slot].rndv_seen = priv->rndv_flags;
        iface->tag.cancel_ctx[priv->slot].force     = 1;
    }

    cmd.command.opcode = C_CMD_TGT_UNLINK;
    cmd.ptl_list       = C_PTL_LIST_PRIORITY;
    cmd.ptlte_index    = iface->tag.ptn;
    cmd.buffer_id      = priv->slot;

    /* The UNLINK must not be lost to a full command queue: for force=1 the
     * cancel is already "assumed successful" by UCP, which will not retry
     * it. */
    return uct_cxi_iface_tgt_post(iface, &cmd);
}
