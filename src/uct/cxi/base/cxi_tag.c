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
 * (software-Get tracking and parked rendezvous confirmations), so no
 * registration is needed. */
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
 * uct_cxi_iface_tag_unexp_init -- the entries that hold unexpected messages
 * until they are reported (see uct_cxi_unexp_report_t in cxi_tag.h): one
 * registered array of tag.unexp_max, as every message in it is an unexpected
 * arrival we are yet to report, and that is as many as the credits let senders
 * have outstanding (each holds at least the slots of an eager message), or
 * tag.max_outstanding, the bound of the pools beside it, without flow
 * control.
 * Registered because each entry is also the landing buffer of its own address
 * read. Only LAC 0 can be reached by the senders' RMA PTEs.
 *
 * With them, the streams (one per sender and tag that has an entry, so at
 * most as many as entries) and the table to find a stream by that key,
 * sized for all of them so that it never has to grow. (khash still
 * rehashes, with a temporary allocation, when deleted keys pile up; a put
 * that fails then is reported, as a stream that could not be made.)
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

/*
 * uct_cxi_iface_tag_init_recv_le -- build tag.recv_le, the priority-list entry
 * of every posted receive but for what differs between receives (the slot,
 * the buffer and the tag to match), which uct_cxi_iface_tag_recv_zcopy() fills
 * in. Needs tag.ptn.
 */
static void uct_cxi_iface_tag_init_recv_le(uct_cxi_iface_t *self)
{
    struct c_target_cmd *le = &self->tag.recv_le;

    le->command.opcode        = C_CMD_TGT_APPEND;
    le->ptl_list              = C_PTL_LIST_PRIORITY;
    le->ptlte_index           = self->tag.ptn;
    le->op_put                = 1;
    le->op_get                = 0;
    le->use_once              = 1;
    le->manage_local          = 1; /* mandatory even for a single-message LE
                                   * -- makes Cassini ignore initiator
                                   * remote_offset (libfabric's own
                                   * _cxip_recv_req() comment) */
    le->unexpected_hdr_disable = 0; /* empirically confirmed to have no
                                     * effect on priority-list APPENDs
                                     * either way -- left at the real
                                     * default */
    le->unrestricted_body_ro  = 1;
    le->unrestricted_end_ro   = 1;
    le->event_link_disable    = 1; /* no append-ack needed */
    le->event_unlink_disable  = 1; /* Suppress the event for the automatic
                                   * (use_once-on-match) unlinkevent.
                                   * The separate, explicit C_CMD_TGT_UNLINK
                                   * issued by tag_recv_cancel() has its
                                   * own event_unlink_disable setting left
                                   * on. Thus, every C_EVENT_UNLINK on PTE
                                   * priority list is a cancel confirmation. */
    le->no_truncate           = 0; /* allow truncated delivery so
                                   * UCS_ERR_TRUNCATED can be reported,
                                   * unlike AM which rejects outright */
    le->restart_seq           = 0;
    le->match_id              = CXI_MATCH_ID_ANY;
}

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
 * uct_cxi_iface_size_tag_ring -- resolve the number and size of the overflow
 * buffers. \a outstanding is the most bytes that the peers allowed to send at
 * once may have sent and not yet had processed (active senders x tag byte
 * window), or 0 when flow control is off and nothing bounds it.
 *
 * Messages are placed back to back, and the NIC retires a buffer once less
 * than max_msg is left in it, so every buffer takes at least
 * (buf_size - max_msg) bytes before it is retired. A message is processed in
 * the order the NIC matched it, and a retired buffer is reposted when the last
 * message in it has been, so the unprocessed bytes sit in the buffers after the
 * one being processed. Allow for those, for the buffer being processed (it may
 * be mostly processed and yet cannot be reposted), and for one more that is
 * linked to take the next message:
 *
 *    num_bufs = floor(outstanding / (buf_size - max_msg)) + 2
 *
 * (The same as for the AM ring, whose messages have an 8-byte header.)
 */
static void uct_cxi_iface_size_tag_ring(uct_cxi_iface_t *self,
                                        const uct_cxi_iface_config_t *config,
                                        size_t outstanding)
{
    size_t        max_msg  = self->tag.max_msg;
    size_t        min_size = 2 * max_msg;
    size_t        buf_size;
    unsigned long num_bufs;
    unsigned long needed   = 0;

    if (config->tag_ovf_buf_size != UCS_MEMUNITS_AUTO) {
        buf_size = config->tag_ovf_buf_size;
    } else if (outstanding != 0) {
        buf_size = ucs_max((size_t)UCT_CXI_TAG_OVF_BUF_SIZE_MIN,
                           UCT_CXI_TAG_OVF_BUF_PER_MSG * max_msg);
    } else {
        buf_size = UCT_CXI_TAG_OVF_BUF_SIZE_DEFAULT;
    }

    if (buf_size < min_size) {
        if (config->tag_ovf_buf_size != UCS_MEMUNITS_AUTO) {
            ucs_warn("cxi TAG_OVERFLOW_BUF_SIZE=%zu is too small for %zu-byte "
                     "messages: using %zu", buf_size, max_msg, min_size);
        }
        buf_size = min_size;
    }

    if (outstanding != 0) {
        needed = outstanding / (buf_size - max_msg) + 2;
    }

    if (config->tag_ovf_num_bufs == UCS_ULUNITS_AUTO) {
        num_bufs = (outstanding != 0) ? needed : UCT_CXI_TAG_OVF_NUM_BUFS_DEFAULT;
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

    /* UCT_CXI_TAG_MAX_OUTSTANDING_MAX leaves the one buffer_id that
     * SEARCH_AND_DELETE uses (UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID) below
     * the hardware's real 65535 ceiling. */
    self->tag.max_outstanding = ucs_min(config->tag_max_outstanding,
                                        UCT_CXI_TAG_MAX_OUTSTANDING_MAX);

    /* A message always fits what is left of the buffer it matched if that is
     * at least the LE's min_free, which is the largest message; and a buffer
     * of twice that holds at least one message before it is retired, as for
     * the AM ring. */
    self->tag.max_msg = uct_cxi_tag_max_msg(config);
    if (self->tag.max_msg < config->tag_eager_max) {
        ucs_warn("cxi TAG_EAGER_MAX=%zu exceeds the %u bytes that min_free can "
                 "express: limiting the eager size to it",
                 config->tag_eager_max, UCT_CXI_AM_MAX_MSG_LIMIT);
    }
    uct_cxi_iface_size_tag_ring(self, config, byte_credits);

    /* What can be unexpected at once: every message the peers' windows allow
     * that goes to the overflow list holds at least an eager message's slots
     * until it is reported; a receive posted for each is the most there are
     * without flow control. */
    self->tag.unexp_max = self->tag.max_outstanding;
    if (slot_credits != 0) {
        self->tag.unexp_max = ucs_max(self->tag.unexp_max,
                                      slot_credits / UCT_CXI_FC_SLOTS_TAG_EAGER);
    }
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

    /* Per-peer unexpected-rndv header cache -- see uct_cxi_rndv_peer_hdr_t
     * in cxi_iface.h. Growable, starts empty; never fails to init. */
    kh_init_inplace(uct_cxi_rndv_peer_hash, &self->tag.rndv_peer_cache);
    kh_init_inplace(uct_cxi_eager_pair_hash, &self->tag.eager_pairs);
    if ((slot_credits != 0) &&
        (kh_resize(uct_cxi_eager_pair_hash, &self->tag.eager_pairs,
                   self->tag.unexp_max) < 0)) {
        /* Never more messages wait for their other event than are unexpected;
         * sized for all of them, a put does not have to allocate. */
        status = UCS_ERR_NO_MEMORY;
        goto err_free_rndv_peer_cache;
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
    ucs_free(self->tag.cancel_ctx);
    ucs_free(self->tag.free_list);
    ucs_free(self->tag.ctx);
}


/*
 * uct_cxi_iface_rdzv_table_init -- the address table (see iface->rdzv.
 * addr_table in cxi_iface.h): one registered slot for every possible 8-bit
 * rendezvous id, so a read by a peer can never fall outside it. LAC 0 only,
 * as that is all the RMA PTE a peer reads it through serves.
 */
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
 * uct_cxi_iface_tag_ovf_maybe_repost -- shared by both the increment side
 * (tag_handle_ovf_arrival()) and the decrement side (uct_cxi_iface_tag_ovf_
 * release()): repost this buffer generation once its refcnt reads exactly
 * 0 and a repost is pending. Checked from both sides, not just after a
 * decrement, because a decrement is not guaranteed to be delivered after
 * its matching increment -- confirmed on real hardware (a second cluster
 * hit ovf_refcnt[buf_idx]==0 inside uct_cxi_iface_tag_ovf_release(), i.e. a
 * decrement landed before tag_handle_ovf_arrival()'s own increment for that
 * same arrival). In that ordering, the increment -- which can also be the
 * generation's true last arrival, setting ovf_repost_pending for the first
 * time -- can itself be the op that brings refcnt back to exactly 0; if
 * only the decrement side checked this, that repost would never fire.
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
 * No assert on ovf_refcnt here (there used to be one, requiring it be >0
 * before decrementing): a decrement landing before its matching increment
 * is a real, confirmed occurrence (see uct_cxi_iface_tag_ovf_maybe_
 * repost()'s doc comment), not a bug to catch -- ovf_refcnt is signed
 * specifically to tolerate that transient negative value until the
 * out-of-order increment brings it back to net zero.
 */
static inline void
uct_cxi_iface_tag_ovf_release(uct_cxi_iface_t *iface, int buf_idx)
{
    iface->tag.ovf_refcnt[buf_idx]--;
    uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
}

/*
 * uct_cxi_tag_credit_return -- the credits \a initiator was charged for a
 * message that went to the overflow list, which the target tracks, are ours
 * to give back now that we are done with it: \a slots event slots and the
 * buffer space of its \a length bytes (as sent: a receive posted too small
 * for it takes fewer, but its sender was charged them all). A sender without flow control has no
 * record and was charged nothing. (A message that matched a posted receive is
 * never tracked: its sender takes the charge back when its ACK says so.)
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
 * uct_cxi_tag_ovf_done -- an unexpected eager message is done with: the
 * reference it holds on its overflow buffer generation is released (\a
 * buf_idx, or -1 for a message with no data there), and its sender's credits
 * given back. They go together because they end together: the message is out
 * of the NIC's unexpected list and its data has been copied out or given up
 * on. The release comes first, so that the credit is never back before the
 * buffer can be reused.
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
 * uct_cxi_iface_tag_report_unexp_eager -- report an unexpected eager message
 * to UCP: the work of uct_cxi_iface_tag_handle_search_delete_confirm_eager()
 * (below), done at once or, if the message has to wait behind an unexpected
 * rendezvous of the same sender, later from a copy of the same event.
 *
 * The "found and
 * deleted" confirmation for our own SEARCH_AND_DELETE: a
 * C_EVENT_PUT_OVERFLOW on the tag PTE whose buffer_id falls in the
 * UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID (see its doc comment in cxi_tag.h).
 * Dispatched directly from
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
 * buf_idx comes from event->tgt_long.start, the address of the message
 * itself: the command's buffer_id says which arrival the SEARCH_AND_DELETE
 * was posted for, but it deletes the oldest entry with that tag, which can
 * be another message. start also locates the actual bytes to copy within
 * the overflow buffer (SEARCH_AND_DELETE only removes the list *entry*, it
 * has no destination-address field of its own to move data with --
 * confirmed against every libfabric SEARCH/SEARCH_AND_DELETE call site). This is the only event that will ever fire for this specific
 * arrival (real hardware search-on-append can never also independently
 * claim an entry our own use_once=1 SEARCH_AND_DELETE already found and
 * deleted), so this is also where the arrival's own overflow-buffer
 * reference is released and its sender's credits are given back.
 */
static void
uct_cxi_iface_tag_report_unexp_eager(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    uint32_t len      = event->tgt_long.mlength;
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    uint32_t sent_len  = event->tgt_long.rlength;
    /* From where the message sits, not from the command's buffer_id: the
     * SEARCH_AND_DELETE took the oldest entry with this tag, which need not
     * be the arrival it was posted for, and the reference to release is
     * that message's own. */
    int      buf_idx = (len > 0) ? uct_cxi_iface_tag_ovf_buf_idx(
                                           iface, event->tgt_long.start) : -1;
    uint64_t tag      = event->tgt_long.match_bits;
    uint64_t imm      = event->tgt_long.header_data;
    void    *context = NULL;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /* Not expected to be reachable with use_once=1 -- see this
         * function's own doc comment. Still release rather than leak if
         * it ever is; there is no companion event to fall back on for
         * this buf_idx otherwise. Guarded on len>0 like every other release
         * here -- a reference was only ever taken for this arrival if its
         * own mlength was >0 (see ovf_refcnt's doc comment in cxi_iface.h),
         * and len is that same mlength. No credits go back: if no message was
         * in fact taken off the list, the one still there will be, and give
         * them back then. */
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

    /* Hand eager_cb the payload where it already sits, in the overflow ring.
     * No UCT_CB_PARAM_FLAG_DESC is offered, so by the uct_tag_unexp_eager_cb_t
     * contract eager_cb must copy out synchronously whatever it wants to keep
     * (UCP does: it unpacks into a matched receive, or copies into its own
     * receive descriptor); the pointer is not retained after it returns. This
     * arrival's overflow reference is still held during the call, so no
     * repost can overwrite the payload, even if eager_cb re-enters progress.
     * Release only afterwards: releasing first can trigger a repost
     * (uct_cxi_iface_post_tag_ovf_le()), making this exact memory eligible
     * for the NIC to overwrite with a new arrival.
     *
     * Nothing after the call may read \a event: a re-entrant progress call
     * from eager_cb can recycle its slot in the event queue. */
    (void)iface->tag.eager_cb(iface->tag.eager_arg,
                              (len > 0) ? uct_cxi_iface_tag_ovf_data(
                                      iface, buf_idx, event->tgt_long.start) :
                                          NULL,
                              len, UCT_CB_PARAM_FLAG_FIRST, tag, imm,
                              &context);

    /* Copied out by eager_cb: the sender's credits are free to go back. */
    uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
}

/* -------------------------------------------------------------------------
 * Held unexpected reports (see uct_cxi_unexp_report_t in cxi_tag.h)
 * -------------------------------------------------------------------------
 */

static void uct_cxi_unexp_read_comp(uct_cxi_send_op_t *op, ucs_status_t status);

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
    ucs_list_head_init(&stream->entries);
    stream->tag       = tag;
    stream->initiator = initiator;
    stream->num_early = 0;
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

    stream->next_free            = iface->tag.unexp_stream_free;
    iface->tag.unexp_stream_free = stream;
}

/* Take an entry for \a event, with \a flags already seen, and put it in the
 * chain of its stream where \a seq, the number of its arrival, puts it: at the
 * end, unless a later arrival has an entry already (an eager message is held
 * only when its SEARCH_AND_DELETE finds it, which can be after the arrival of
 * a rendezvous that was sent after it). NULL if all entries or streams are in
 * use. */
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
    stream->num_early += !(flags & UCT_CXI_UNEXP_ARRIVED);
    iface->tag.unexp_held += is_rndv;
    return e;
}

/* Take an entry off its chain; it is not free until uct_cxi_unexp_free(), and
 * its stream, if now empty, is the caller's to give back. */
static void uct_cxi_unexp_unlink(uct_cxi_iface_t *iface,
                                 uct_cxi_unexp_report_t *e)
{
    ucs_list_del(&e->link);
    e->stream->num_early -= !(e->flags & UCT_CXI_UNEXP_ARRIVED);
    iface->tag.unexp_held -= e->is_rndv;
    if (!ucs_list_is_empty(&e->wait)) {
        ucs_list_del(&e->wait);
        ucs_list_head_init(&e->wait);
    }
}

/*
 * Give back an entry that is off its chain. For a rendezvous that has arrived
 * this is where the sender's credits go back: every event the message leaves
 * in the receive event queue has been handled by now (its arrival, the outcome
 * of the search for it, the completion of the read of its source address, which
 * for a message a receive took is the last to come), and it holds no more of
 * the table. All the ways of leaving the table end here, so the credits go
 * back once.
 */
static void uct_cxi_unexp_free(uct_cxi_iface_t *iface,
                               uct_cxi_unexp_report_t *e)
{
    if (e->is_rndv && (e->flags & UCT_CXI_UNEXP_ARRIVED)) {
        uct_cxi_tag_credit_return(iface, e->initiator,
                                  UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
    }

    e->next_free          = iface->tag.unexp_free;
    iface->tag.unexp_free = e;
}

/* The arrival of an entry is seen. */
static void uct_cxi_unexp_set_arrived(uct_cxi_unexp_report_t *e)
{
    e->stream->num_early -= !(e->flags & UCT_CXI_UNEXP_ARRIVED);
    e->flags             |= UCT_CXI_UNEXP_ARRIVED;
}

/* A rendezvous that is not ours, now that it has arrived: nothing is left to
 * wait for, but its address read, if one is on its way. */
static void uct_cxi_unexp_discard(uct_cxi_iface_t *iface,
                                  uct_cxi_unexp_report_t *e)
{
    uct_cxi_unexp_unlink(iface, e);
    if (e->state != UCT_CXI_UNEXP_READING) {
        uct_cxi_unexp_free(iface, e);
    } /* else uct_cxi_unexp_read_comp() frees it: the read cannot be undone */
}

/*
 * The entry of the rendezvous \a event is about in \a stream, that has not
 * had the event(s) in \a absent yet: the oldest one, as the sender reuses a
 * rendezvous_id only after the message with it was pulled, and by then a lost
 * one has had all it will have (and is off the chain). A stream is short, and
 * an event is for an entry at or near its head when events come in the order
 * of the messages: this is not a scan of everything held.
 */
static uct_cxi_unexp_report_t *
uct_cxi_unexp_find(uct_cxi_unexp_stream_t *stream, const union c_event *event,
                   unsigned absent)
{
    uint8_t                 id = event->tgt_long.rendezvous_id;
    uct_cxi_unexp_report_t *e;

    if ((absent == UCT_CXI_UNEXP_ARRIVED) && (stream->num_early == 0)) {
        return NULL; /* every one of them has arrived already */
    }

    ucs_list_for_each(e, &stream->entries, link) {
        if (e->is_rndv && (e->rendezvous_id == id) && !(e->flags & absent)) {
            return e;
        }
    }
    return NULL;
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
 * Post the read of the source address of \a e's rendezvous: 8 bytes from
 * slot rendezvous_id of the sender's address table, with the same restricted
 * RMA Get any endpoint would use against its RMA PTE (LAC 0, pid_offset 0).
 * The sender's address is built from the event's initiator -- there is no
 * endpoint to the sender here, tag receives belong to the interface -- and
 * the table's base address is what its announce told us.
 *
 * The read itself is not waited for; only for room in the command queue, if
 * it is full, as everywhere else this interface posts a command from an event
 * handler (the NIC empties it without any help from us). The REPLY is on the
 * RX queue, as for the other Gets issued from an event handler (which cannot
 * be refused for lack of a TX queue slot). UCS_ERR_NO_ELEM: the sender's
 * announce has not been seen yet.
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

/*
 * Post the address read of the rendezvous \a e if it can be: not yet posted,
 * its sender known, and it is not known to be lost. If the sender is not
 * known (its announce is not seen), the entry waits for the announce handler.
 */
static void uct_cxi_unexp_start(uct_cxi_iface_t *iface,
                                uct_cxi_unexp_report_t *e)
{
    ucs_status_t status;

    if (!e->is_rndv || (e->state != UCT_CXI_UNEXP_NEW) ||
        (e->flags & UCT_CXI_UNEXP_LOST) || !ucs_list_is_empty(&e->wait)) {
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

/* Can \a e be reported to UCP, as far as it itself goes? A rendezvous must be
 * ours, and have its address (or know it can not get it). */
static UCS_F_ALWAYS_INLINE int
uct_cxi_unexp_is_ready(const uct_cxi_unexp_report_t *e)
{
    return !e->is_rndv ||
           (((e->flags & (UCT_CXI_UNEXP_ARRIVED | UCT_CXI_UNEXP_OWNED)) ==
             (UCT_CXI_UNEXP_ARRIVED | UCT_CXI_UNEXP_OWNED)) &&
            ((e->state == UCT_CXI_UNEXP_READY) ||
             (e->state == UCT_CXI_UNEXP_FAILED)));
}

/*
 * Report \a e, which is off its stream's chain, to UCP and give it back. The
 * entry is released first and the report made from copies, as the callback
 * may re-enter progress.
 *
 * For a rendezvous, rndv_cb gets what UCP's later pull needs:
 *   - header/header_length: this sender's cached {ep_id, md_index} (its
 *     announce) plus this message's own req_id (header_data).
 *   - remote_addr: the source address read from the sender's table.
 *   - rkey_buf: a stack uct_cxi_rkey_t with is_rndv=1 and rendezvous_id --
 *     enough for UCP's later uct_ep_get_zcopy/bcopy to reach the sender's
 *     rendezvous source PTE through its own uct_ep, whose rem_nid/rem_pid
 *     already identify the peer. No real memory key exists to pack here.
 * flags=0, as the reference HW-tag-offload transport (uct_rc_mlx5_handle_
 * unexp_rndv()) passes: a rendezvous report is never fragmented.
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
 * chain, if it is ready, and then the next, until one is not. Anything behind
 * an entry that is not ready waits for it, and only these are looked at: other
 * streams do not wait for this one.
 *
 * A report can call into UCP, which may make progress again on this interface
 * and bring events for this stream: while busy the stream is not advanced
 * again nor given back, and this loop picks up what they did.
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
    if (e->flags & UCT_CXI_UNEXP_LOST) {
        /* Its message went to a receive; this read was for nothing. It is
         * off its chain, which may be gone too. */
        uct_cxi_unexp_free(e->iface, e);
        return;
    }
    uct_cxi_unexp_advance(e->iface, e->stream);
}

/* Advance the stream of the rendezvous \a event is about, if there is one. */
static void uct_cxi_unexp_advance_event(uct_cxi_iface_t *iface,
                                        const union c_event *event)
{
    uct_cxi_unexp_stream_t *stream =
            uct_cxi_unexp_stream_find(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);

    if (stream != NULL) {
        uct_cxi_unexp_advance(iface, stream);
    }
}

/*
 * The announce of \a initiator has been seen: post the address reads of its
 * rendezvous that were waiting for it. The wait list is looked at again from
 * the start after each, as a failed read is reported, which can call into UCP.
 */
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

/* The rendezvous \a event is about has arrived in the overflow list. */
static void uct_cxi_unexp_rndv_arrived(uct_cxi_iface_t *iface,
                                       const union c_event *event,
                                       uint64_t seq)
{
    uct_cxi_unexp_stream_t *stream =
            uct_cxi_unexp_stream_find(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);
    uct_cxi_unexp_report_t *e = (stream == NULL) ? NULL :
            uct_cxi_unexp_find(stream, event, UCT_CXI_UNEXP_ARRIVED);

    if (e == NULL) {
        e = uct_cxi_unexp_alloc(iface, event, 1, UCT_CXI_UNEXP_ARRIVED, seq);
        if (ucs_unlikely(e == NULL)) {
            ucs_error("cxi TAG no free entry to track an unexpected "
                      "rendezvous, tag=0x%lx initiator=0x%x",
                      (unsigned long)event->tgt_long.match_bits,
                      (unsigned)event->tgt_long.initiator.initiator.process);
            /* Nothing will ever free an entry for it: its credits go back
             * now. */
            uct_cxi_tag_credit_return(
                    iface, event->tgt_long.initiator.initiator.process,
                    UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
            return;
        }
        uct_cxi_unexp_start(iface, e);
        return;
    }

    uct_cxi_unexp_set_arrived(e);
    if (e->flags & UCT_CXI_UNEXP_LOST) {
        uct_cxi_unexp_discard(iface, e); /* the tombstone */
    } else {
        uct_cxi_unexp_start(iface, e);
    }
}

/* The rendezvous \a event is about was found and deleted by our own
 * SEARCH_AND_DELETE: it is ours to report. */
static UCS_F_ALWAYS_INLINE void uct_cxi_unexp_rndv_owned(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    uct_cxi_unexp_stream_t *stream =
            uct_cxi_unexp_stream_find(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);
    uct_cxi_unexp_report_t *e = (stream == NULL) ? NULL :
            uct_cxi_unexp_find(stream, event,
                               UCT_CXI_UNEXP_OWNED | UCT_CXI_UNEXP_LOST);

    if (e != NULL) {
        e->flags |= UCT_CXI_UNEXP_OWNED;
    } else {
        e = uct_cxi_unexp_alloc(iface, event, 1, UCT_CXI_UNEXP_OWNED,
                                iface->tag.unexp_seq++);
        if (ucs_unlikely(e == NULL)) {
            ucs_error("cxi TAG no free entry to hold an unexpected "
                      "rendezvous, tag=0x%lx initiator=0x%x -- dropped",
                      (unsigned long)event->tgt_long.match_bits,
                      (unsigned)event->tgt_long.initiator.initiator.process);
            return;
        }
    }

    uct_cxi_unexp_start(iface, e);
    uct_cxi_unexp_advance(iface, e->stream);
}

/*
 * The rendezvous \a event is about went to a receive posted after it arrived
 * (the delayed match, a C_EVENT_PUT_OVERFLOW on that receive's slot), or is
 * to be given up for another reason: not ours. If it has not arrived yet,
 * only a tombstone is left for its arrival to remove.
 */
static void uct_cxi_unexp_rndv_lost(uct_cxi_iface_t *iface,
                                    const union c_event *event)
{
    uct_cxi_unexp_stream_t *stream =
            uct_cxi_unexp_stream_find(iface,
                                      event->tgt_long.initiator.initiator.process,
                                      event->tgt_long.match_bits);
    uct_cxi_unexp_report_t *e = (stream == NULL) ? NULL :
            uct_cxi_unexp_find(stream, event,
                               UCT_CXI_UNEXP_OWNED | UCT_CXI_UNEXP_LOST);

    if (e == NULL) {
        ucs_debug("cxi TAG [UNEXP-LOST-FIRST] tag=0x%lx id=%u: claimed before "
                  "it was seen arriving",
                  (unsigned long)event->tgt_long.match_bits,
                  (unsigned)event->tgt_long.rendezvous_id);
        if (ucs_unlikely(uct_cxi_unexp_alloc(iface, event, 1,
                                             UCT_CXI_UNEXP_LOST,
                                             iface->tag.unexp_seq++) == NULL)) {
            ucs_error("cxi TAG no free entry to note a rendezvous claimed by "
                      "a receive, tag=0x%lx initiator=0x%x",
                      (unsigned long)event->tgt_long.match_bits,
                      (unsigned)event->tgt_long.initiator.initiator.process);
        }
        return;
    }

    e->flags |= UCT_CXI_UNEXP_LOST;
    ucs_debug("cxi TAG [UNEXP-LOST] tag=0x%lx id=%u state=%u flags=0x%x",
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rendezvous_id, (unsigned)e->state,
              (unsigned)e->flags);
    stream = e->stream;
    if (e->flags & UCT_CXI_UNEXP_ARRIVED) {
        uct_cxi_unexp_discard(iface, e);
    }

    /* What was held behind it is free to go. */
    uct_cxi_unexp_advance(iface, stream);
}

/* -------------------------------------------------------------------------
 * Pairing the two events of an unexpected eager message
 * -------------------------------------------------------------------------
 */

static void uct_cxi_tag_found_eager(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint64_t seq);
static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
                                             const union c_event *event);

/*
 * A match event (a posted receive's delayed match, or our SEARCH_AND_DELETE's
 * find) of an eager message with data is about to be handled: it copies from
 * the overflow buffer, so it may only be once the message's arrival event has
 * been seen -- the Put that was written after its data (see
 * uct_cxi_eager_pair_t). Returns 1 if it has, and the match goes on, with the
 * number of the arrival in *seq_p. If not,
 * the event is kept for uct_cxi_eager_arrived() to carry on with, and 0 is
 * returned.
 */
static int uct_cxi_eager_match_ready(uct_cxi_iface_t *iface,
                                     const union c_event *event, int is_found,
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

    pair           = &kh_value(&iface->tag.eager_pairs, k);
    pair->parked   = 1;
    pair->is_found = is_found;
    pair->event    = *event;
    ucs_debug("cxi TAG [EAGER-MATCH-EARLY] start=0x%lx %s before its arrival",
              (unsigned long)event->tgt_long.start,
              is_found ? "found" : "delayed match");
    return 0;
}

/*
 * The arrival event of an unexpected eager message with data has been
 * handled. If its match came first, carry on with it now; if not, note the
 * arrival for the match.
 */
static void uct_cxi_eager_arrived(uct_cxi_iface_t *iface,
                                  const union c_event *event, uint64_t seq)
{
    uct_cxi_eager_pair_t pair;
    khiter_t             k;
    int                  ret;

    k = kh_get(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start);
    if (k == kh_end(&iface->tag.eager_pairs)) {
        k = kh_put(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
                   event->tgt_long.start, &ret);
        if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
            ucs_error("cxi TAG cannot note the arrival of the unexpected "
                      "eager message at 0x%lx: out of memory",
                      (unsigned long)event->tgt_long.start);
            return;
        }
        kh_value(&iface->tag.eager_pairs, k).parked = 0;
        kh_value(&iface->tag.eager_pairs, k).seq    = seq;
        return;
    }

    pair = kh_value(&iface->tag.eager_pairs, k);
    kh_del(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs, k);
    if (!pair.parked) {
        ucs_error("cxi TAG a second arrival of the unexpected eager message "
                  "at 0x%lx", (unsigned long)event->tgt_long.start);
        return;
    }

    /* The handlers may call into UCP; nothing of ours is referenced after. */
    if (pair.is_found) {
        uct_cxi_tag_found_eager(iface, &pair.event, seq);
    } else {
        uct_cxi_tag_eager_match_complete(iface, &pair.event);
    }
}

/*
 * uct_cxi_iface_tag_handle_search_delete_confirm_eager -- the "found and
 * deleted" confirmation of our SEARCH_AND_DELETE for an unexpected eager
 * message (see uct_cxi_iface_tag_report_unexp_eager() above for the event).
 * Reported at once, unless an unexpected message with the same tag from the
 * same sender that arrived before it is still held (a rendezvous waiting for
 * its address): UCP must hear of that first, and this waits behind it, in the
 * place its arrival number \a seq gives it. The test costs one load when no
 * rendezvous is held.
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
            if (uct_cxi_unexp_alloc(iface, event, 0,
                                    UCT_CXI_UNEXP_ARRIVED |
                                    UCT_CXI_UNEXP_OWNED, seq) != NULL) {
                return;
            }
            ucs_warn("cxi TAG no free entry to hold an unexpected eager "
                     "message behind an unexpected rendezvous: reporting it "
                     "out of order");
        }
    }

    uct_cxi_iface_tag_report_unexp_eager(iface, event);
}

void
uct_cxi_iface_tag_handle_search_delete_confirm_eager(uct_cxi_iface_t *iface,
                                                     const union c_event *event)
{
    uint64_t seq;

    if ((cxi_event_rc(event) != C_RC_OK) || (event->tgt_long.mlength == 0)) {
        /* No data in the overflow buffer to wait for, and no record of its
         * arrival: it counts as the latest. */
        seq = iface->tag.unexp_seq++;
    } else if (!uct_cxi_eager_match_ready(iface, event, 1, &seq)) {
        return; /* its arrival is yet to come: see uct_cxi_eager_arrived() */
    }

    uct_cxi_tag_found_eager(iface, event, seq);
}

/*
 * uct_cxi_iface_handle_rndv_hdr_announce -- receive-side handler for the
 * one-time-per-ep control message sent by uct_cxi_ep_send_rndv_hdr_announce
 * (cxi_am.c). Dispatched from cxi_iface.c's AM handling before ever
 * reaching uct_iface_invoke_am() -- this is not a real user AM. Populates
 * this initiator's entry in iface->tag.rndv_peer_cache, then lets whatever
 * of its unexpected rendezvous was waiting for it go on.
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
 * uct_cxi_iface_tag_handle_search_delete_confirm_rndv -- rendezvous
 * counterpart of tag_handle_search_delete_confirm_eager() above (buffer_id in
 * the disjoint RNDV range). No payload to copy -- a rendezvous message's data
 * is pulled later by UCP's own generic Get, not delivered inline. mlength is
 * always 0 here (a rendezvous Put never eager-attaches anything -- see
 * uct_ep_tag_rndv_zcopy), so this never touches the overflow buffer at all.
 *
 * This is the OWNED event of uct_cxi_unexp_report_t: it matches the entry
 * made when the message arrived, by the event's own initiator and
 * rendezvous_id, whichever command found it. It is reported when the sender's
 * source address, which the hardware does not give us, has been read.
 */
void
uct_cxi_iface_tag_handle_search_delete_confirm_rndv(uct_cxi_iface_t *iface,
                                                    const union c_event *event)
{
    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /* See tag_handle_search_delete_confirm_eager()'s own doc comment --
         * not expected to be reachable with use_once=1. Nothing to release
         * (mlength is always 0 for rendezvous, so no ovf_refcnt reference
         * was ever taken for this arrival). */
        ucs_error("cxi TAG [SEARCH-DELETE-RNDV-UNEXPECTED-RC] tag=0x%lx "
                  "rc=%d", (unsigned long)event->tgt_long.match_bits,
                  cxi_event_rc(event));
        return;
    }

    ucs_info("cxi TAG [SEARCH-DELETE-RNDV-MATCH] tag=0x%lx rlength=%u "
             "rendezvous_id=%u", (unsigned long)event->tgt_long.match_bits,
             (unsigned)event->tgt_long.rlength,
             (unsigned)event->tgt_long.rendezvous_id);

    uct_cxi_unexp_rndv_owned(iface, event);
}

/*
 * uct_cxi_iface_tag_ovf_failed -- a Put the NIC could not place in an overflow
 * buffer. Rare, kept out of line. The event reports the failure and carries
 * no message: there is nothing to look for or to hand on, no data to protect,
 * and nothing to give back (the sender is told of the failure in its own ACK,
 * and takes its credits back itself). The usual cause is a message longer than
 * what is left of the buffer it matched, which is not tried against the next
 * one; the buffers' min_free is the largest message to prevent that.
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
    uint64_t seq      = iface->tag.unexp_seq++; /* the order of arrivals */
    struct c_target_cmd sd = {};
    ucs_status_t status;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        uct_cxi_iface_tag_ovf_failed(iface, event);
        return;
    }

    if (event->tgt_long.mlength > 0) {
        iface->tag.ovf_refcnt[buf_idx]++;
        /* Checked here too, not just from uct_cxi_iface_tag_ovf_release() --
         * see uct_cxi_iface_tag_ovf_maybe_repost()'s own doc comment for why
         * this side needs it as well. */
        uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
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
     * buffer_id is the one reserved UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID
     * for every arrival, eager or rendezvous: it only marks the event as the
     * outcome of a SEARCH_AND_DELETE. Which message that is, and of which
     * kind, is read from the event itself (see that macro's doc comment). */
    if (event->tgt_long.rendezvous) {
        uct_cxi_unexp_rndv_arrived(iface, event, seq);
    }

    sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
    sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    sd.ptlte_index    = iface->tag.ptn;
    sd.match_bits     = tag;
    sd.ignore_bits    = 0;
    sd.match_id       = CXI_MATCH_ID_ANY;
    sd.length         = -1U;
    sd.use_once       = 1;
    sd.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID;

    /* uct_cxi_iface_tgt_post() waits out a full target command queue. There
     * is no safe way to confirm exclusive ownership of this message without
     * the SEARCH_AND_DELETE landing, so only if the queue stays wedged for
     * the whole timeout is the message not handed off at all. It is then
     * still in the NIC's unexpected list: whatever claims it later (a receive
     * posted for its tag) finds it there and ends it as for any other, so its
     * buffer reference and its sender's credits are left for that, and
     * nothing is released or given back here. */
    status = uct_cxi_iface_tgt_post(iface, &sd);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi TAG SEARCH_AND_DELETE post failed: %s -- unexpected "
                  "message tag=0x%lx is not reported unless a receive claims "
                  "it", ucs_status_string(status), (unsigned long)tag);
    }

    if (event->tgt_long.rendezvous) {
        /* Its address read went out alongside the SEARCH_AND_DELETE; what
         * waited for this arrival can go on. */
        uct_cxi_unexp_advance_event(iface, event);
    } else if (event->tgt_long.mlength > 0) {
        uct_cxi_eager_arrived(iface, event, seq);
    }
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
 * local_addr is the destination buffer's own base address (event->tgt_long.
 * start, fixed at the priority LE's own APPEND time) -- fetches the full
 * [0, rlength) range every time, since a rendezvous Put never eager-attaches
 * anything on this transport (see uct_ep_tag_rndv_zcopy).
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
        cmd.lac                = 0; /* LAC 0 only -- see design plan scoping */
        cmd.event_send_disable = 1;
        cmd.restricted         = 0;
        cmd.initiator          = iface->match_id;
        /* REPLY on the RX queue, where a NIC-issued rendezvous Get's REPLY
         * lands too: this Get is issued from an event handler, which cannot
         * be refused when the TX queue is full, and each posted receive
         * already has a slot budgeted there for exactly one Get REPLY. Any
         * queue's events go through the same dispatch. */
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
 * uct_cxi_iface_tag_match_lookup -- shared prefix for every tag-PTE match
 * handler (eager, rendezvous): the slot/ctx lookup is identical regardless
 * of which kind of match this turns out to be, so it lives here once
 * rather than in each handler. Classifying eager-vs-rendezvous
 * (event->tgt_long.rendezvous) and dispatching to the right handler is the
 * caller's job -- iface_progress() in cxi_iface.c -- not this function's
 * or the handlers' own; see the handlers' doc comments. A
 * SEARCH_AND_DELETE confirmation (buffer_id==UCT_CXI_TAG_SEARCH_DELETE_
 * BUFFER_ID) never reaches here at all -- iface_progress() routes it to
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
 * uct_cxi_tag_eager_match_complete -- a plain eager match, either
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
 * UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID, see cxi_tag.h) either -- that shares this event type and
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
static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
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

    int                      delayed = (event->hdr.event_type ==
                                        C_EVENT_PUT_OVERFLOW);
    uint32_t                 initiator = event->tgt_long.initiator.initiator.
                                         process;
    uint32_t                 sent_len  = event->tgt_long.rlength;

    ctx = uct_cxi_iface_tag_match_lookup(iface, event, &slot);
    if (ctx == NULL) {
        /* The receive is gone, but the message it matched is still ours to be
         * done with. */
        if (delayed) {
            buf_idx = (event->tgt_long.mlength > 0) ?
                      uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start) : -1;
            uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
        }
        return;
    }

    iface->tag.ctx[slot] = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        iface->tag.cancel_ctx[slot].force = 0;
        if (delayed) {
            /* Force-cancelled: the normal path below (which would
             * otherwise do this after its copy) never runs, but the
             * reference taken at arrival still needs releasing or this
             * buffer generation can never repost, and the sender's credits
             * are due back all the same. No copy needed -- ctx is never read
             * on this branch. */
            buf_idx = (event->tgt_long.mlength > 0) ?
                      uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start) : -1;
            uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
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

    if (delayed) {
        /* Delayed match: copy out of the overflow buffer, then release it and
         * give the sender's credits back -- see this function's own doc
         * comment and uct_cxi_tag_ovf_done(). The buffer is gated on
         * mlength>0 like the arrival side's own increment (cxi_iface.h's
         * ovf_refcnt doc comment): an mlength==0 delayed match never took a
         * reference to begin with. */
        buf_idx = -1;
        if (event->tgt_long.mlength > 0) {
            void *data;

            buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start);
            data    = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                 event->tgt_long.start);
            memcpy((void *)(uintptr_t)priv->recv_addr, data,
                   event->tgt_long.mlength);
        }
        uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
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
 * uct_cxi_iface_tag_handle_eager_match -- see uct_cxi_tag_eager_match_complete()
 * above. A delayed match with data waits for the message's arrival event first
 * (uct_cxi_eager_match_ready()): the NIC raises the match from its command
 * pipeline and the arrival from its message pipeline, so the match can be
 * seen before the payload is in the overflow buffer (seen on hardware: stale
 * ring contents copied for the first message into a fresh ring).
 */
void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    uint64_t seq;

    if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
        (event->tgt_long.mlength > 0) &&
        !uct_cxi_eager_match_ready(iface, event, 0, &seq)) {
        return; /* its arrival is yet to come: see uct_cxi_eager_arrived() */
    }

    uct_cxi_tag_eager_match_complete(iface, event);
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
 * real hardware; matches libfabric's rdzv_recv_req_event()); Reply is only
 * ever resolved once C_EVENT_RENDEZVOUS itself has been processed (see that
 * branch below), so it can't race it. tag_consumed_cb fires on the first
 * event regardless: it only signals "don't also match this in software".
 *
 * Checks cancel_ctx[slot].force before touching ctx/priv -- see its doc
 * comment in cxi_iface.h. A force-cancelled slot keeps accumulating via
 * uct_cxi_iface_tag_rdzv_cancel_seen() instead of priv until reclaimed.
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

    if (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) {
        /* The delayed match of a rendezvous that arrived unexpected: ours
         * to track whether or not the receive is still there. */
        uct_cxi_unexp_rndv_lost(iface, event);
    }

    if (ctx == NULL) {
        return;
    }

    seen_bit = (event->hdr.event_type == C_EVENT_RENDEZVOUS) ?
            UCT_CXI_RNDV_SEEN_RNDV : UCT_CXI_RNDV_SEEN_PUT;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
            /* The buffer is already gone (UCP's contract for force=1) --
             * never issue a new Get into it. The main pull's Reply is
             * abandoned when get_issued==0 (no Get was ever issued for it
             * at all), but left pending when get_issued==1 -- hardware's
             * own auto-Get is already in flight regardless of cancellation
             * and will complete normally via uct_cxi_iface_tag_handle_
             * rdzv_reply(), which routes back through this same
             * force-cancel accumulation. */
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
         * mlength is always 0 for a rendezvous arrival, so "rlength >
         * mlength" would be true for nearly every non-empty message,
         * truncated or not. See posted_len's own comment in cxi_tag.h. */
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
    /* get_issued==1 (the common case): the NIC's own auto-issued pull
     * already covers the whole message; its C_EVENT_REPLY lands separately
     * and marks SEEN_REPLY via uct_cxi_iface_tag_handle_rdzv_reply().
     * Nothing to do here. Put/Put_Overflow events need no extra handling
     * either -- mlength is always 0 for a rendezvous arrival (see
     * uct_ep_tag_rndv_zcopy), so there is no header to cache and no
     * overflow-buffer reference to release. */

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
 * uct_cxi_iface_tag_rdzv_reply_done -- completion for a rendezvous
 * receive's pull Get (seen_bit=SEEN_REPLY, via uct_cxi_iface_tag_handle_
 * rdzv_reply or uct_cxi_rdzv_get_comp). Marks seen_bit and fires
 * completed_cb once UCT_CXI_RNDV_SEEN_REQUIRED is satisfied.
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
    unsigned         units = UCT_CXI_FC_UNITS(length);
    ucs_status_t     status;
    int              credited;

    UCT_CHECK_LENGTH(length, 0, C_MAX_IDC_PAYLOAD_UNR, "tag_eager_short");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return UCS_ERR_NO_RESOURCE;
    }

    status = uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG,
                                UCT_CXI_FC_SLOTS_TAG_EAGER, units, &credited);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    status = uct_cxi_ep_idc_send(ep, iface, ep->dfa_tag, ep->dfa_tag_idx_ext,
                                 tag, data, length, UCT_CXI_FC_TAG, units,
                                 credited, "tag_eager_short");
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);

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
    unsigned              units;
    ucs_status_t          status;
    int                   credited;
    int                   ret;

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
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
    unsigned              units  = UCT_CXI_FC_UNITS(length);
    uct_cxi_send_op_t    *op;
    ucs_status_t          status;
    int                   credited;
    int                   ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_eager_zcopy");
    UCT_CHECK_LENGTH(length, 0, iface->tag.max_msg, "tag_eager_zcopy");

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
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
 * header/header_length: UCP passes the full 17-byte offload rendezvous
 * header on every call (ep_id/req_id/md_index, mirrored locally as
 * uct_cxi_rndv_hdr_wire_t). Only req_id varies per send and travels via
 * cmd.header_data on every Put, unconditionally -- the rendezvous Put
 * itself never eager-attaches anything (eager_length=0 always). ep_id/
 * md_index are constant for the life of this ep and instead travel once,
 * lazily, via a separate control message (uct_cxi_ep_send_rndv_hdr_
 * announce, cxi_am.c) on this ep's first call here -- see cxi_ep.h's
 * rndv_hdr_announced and iface->tag.rndv_peer_cache (cxi_iface.h) for the
 * receive side.
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

    if (uct_cxi_ep_fc_blocked(ep, iface, &iface->tag.fc)) {
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    /* Only req_id varies per send (see uct_cxi_rndv_hdr_wire_t) --
     * header_length is always exactly sizeof(uct_cxi_rndv_hdr_wire_t)
     * whenever this offload protocol is in use (see UCT_CXI_TAG_RNDV_
     * MAX_HDR's comment), but guard anyway rather than read past the
     * caller's buffer. */
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

    /* Where a target that takes this off its unexpected list can find the
     * source address (see iface->rdzv.addr_table). A plain store: the Put
     * below is written to the command queue and the doorbell rung after it,
     * and that ordering is all the NIC's later read of the slot needs. */
    iface->rdzv.addr_table[id] = local_addr;

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
    struct c_target_cmd     le    = iface->tag.recv_le;
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
    cmd.ptlte_index    = iface->tag.ptn;
    cmd.buffer_id      = priv->slot;

    /* The UNLINK must not be lost to a full command queue: for force=1 the
     * cancel is already "assumed successful" by UCP, which will not retry
     * it. */
    return uct_cxi_iface_tgt_post(iface, &cmd);
}
