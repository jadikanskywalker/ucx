/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload: eager send/receive and native
 * rendezvous.
 *
 * One PTE with two LE populations (see cxi_tag.h): use_once priority LEs bound
 * to the caller's buffers for direct matches, and an overflow ring for messages
 * with no receive posted yet, which are reported to UCP at once. Short, bcopy
 * and zcopy sends are the same wire Put via ep->dfa_tag, with imm in
 * header_data.
 *
 * The overflow ring is reposted on its terminal C_EVENT_PUT with auto_unlinked.
 * A priority-LE slot is freed by its first disposition event (a match, or an
 * UNLINK with C_RC_OK); the second UNLINK of a cancel that lost to a match
 * (C_RC_ENTRY_NOT_FOUND) is dropped, as libfabric does.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
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


/*
 * Allocate the unexpected-message entries (uct_cxi_unexp_report_t): a
 * registered array of tag.unexp_max, as each entry is also the landing buffer
 * of its address read (LAC 0). Plus the streams (at most one per entry) and the
 * table to find them, sized so it never grows.
 */
static ucs_status_t
uct_cxi_iface_tag_unexp_init(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    size_t page = ucs_get_page_size();
    size_t len  = ucs_align_up(self->tag.unexp_max *
                                       sizeof(uct_cxi_unexp_report_t),
                               page);
    ucs_status_t status;
    unsigned i;
    int ret;

    /* The fields that are looked at along a stream's chain share the first
     * cache line. */
    UCS_STATIC_ASSERT(ucs_offsetof(uct_cxi_unexp_report_t, flags) <
                      UCS_SYS_CACHE_LINE_SIZE);

    kh_init_inplace(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams);
    ucs_list_head_init(&self->tag.unexp_wait);
    ucs_list_head_init(&self->tag.unexp_live);

    self->tag.unexp_stream_pool = ucs_calloc(self->tag.unexp_max,
                                             sizeof(uct_cxi_unexp_stream_t),
                                             "cxi-tag-unexp-streams");
    if (self->tag.unexp_stream_pool == NULL) {
        status = UCS_ERR_NO_MEMORY;
        goto err_streams;
    }
    for (i = 0; i + 1 < self->tag.unexp_max; i++) {
        self->tag.unexp_stream_pool[i].next_free =
                &self->tag.unexp_stream_pool[i + 1];
    }
    self->tag.unexp_stream_free = &self->tag.unexp_stream_pool[0];
    if (kh_resize(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams,
                  2 * self->tag.unexp_max) < 0) {
        status = UCS_ERR_NO_MEMORY;
        goto err_streams;
    }

    ret = ucs_posix_memalign((void**)&self->tag.unexp_ents, page, len,
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
    for (i = 0; i + 1 < self->tag.unexp_max; i++) {
        self->tag.unexp_ents[i].next_free = &self->tag.unexp_ents[i + 1];
    }
    self->tag.unexp_free = &self->tag.unexp_ents[0];
    return UCS_OK;

err_free:
    ucs_free(self->tag.unexp_ents);
    self->tag.unexp_ents = NULL;
err_streams:
    ucs_free(self->tag.unexp_stream_pool);
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
    self->tag.unexp_ents = NULL;
    ucs_free(self->tag.unexp_stream_pool);
    kh_destroy_inplace(uct_cxi_unexp_stream_hash, &self->tag.unexp_streams);
}

/*
 * Build tag.recv_le, the priority LE of every posted receive but for the slot,
 * buffer and tag (filled by uct_cxi_iface_tag_recv_zcopy()). Needs tag.ptn.
 *
 * manage_local is needed even for a single-message LE: Cassini then ignores the
 * initiator's remote_offset (as libfabric). The automatic use_once unlink
 * raises no event but the explicit UNLINK of tag_recv_cancel() does, so every
 * priority-list C_EVENT_UNLINK confirms a cancel. Truncated delivery is allowed
 * to report UCS_ERR_TRUNCATED.
 */
static void uct_cxi_iface_tag_init_recv_le(uct_cxi_iface_t *self)
{
    struct c_target_cmd *le = &self->tag.recv_le;

    memset(le, 0, sizeof(*le));
    le->command.opcode       = C_CMD_TGT_APPEND;
    le->ptl_list             = C_PTL_LIST_PRIORITY;
    le->ptlte_index          = self->tag.ptn;
    le->op_put               = 1;
    le->use_once             = 1;
    le->manage_local         = 1;
    le->unrestricted_body_ro = 1;
    le->unrestricted_end_ro  = 1;
    le->event_link_disable   = 1;
    le->event_unlink_disable = 1;
    le->match_id             = CXI_MATCH_ID_ANY;
}

/* Append one overflow-list LE for ring buffer \a buf_idx. */
static ucs_status_t uct_cxi_iface_post_tag_ovf_le(uct_cxi_iface_t *self,
                                                  int buf_idx, int restart_seq)
{
    void *buf = self->tag.rx_base + (size_t)buf_idx * self->tag.buf_size;
    struct c_target_cmd le = {};
    ucs_status_t status;

    uct_cxi_ring_le_init(&le, self->tag.pte, C_PTL_LIST_OVERFLOW, buf_idx,
                         restart_seq);
    le.lac      = self->tag.rx_mh.cxi_md->lac;
    le.start    = uct_cxi_mem_iova(&self->tag.rx_mh, buf);
    le.length   = self->tag.buf_size;
    le.min_free = self->tag.max_msg;

    status = uct_cxi_iface_tgt_post(self, &le);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi tag overflow LE append buf %d: %s", buf_idx,
                  ucs_status_string(status));
        return status;
    }

    ucs_debug("cxi tag overflow LE append buf %d ptn %u start 0x%lx len %zu "
              "restart_seq %d",
              buf_idx, self->tag.pte->ptn, (unsigned long)le.start,
              self->tag.buf_size, restart_seq);
    return UCS_OK;
}

/*
 * Number and size of the overflow buffers for \a outstanding bytes in flight
 * (active senders x tag byte window). As for the AM ring, without the 8-byte
 * header:
 *
 *    num_bufs = floor(outstanding / (buf_size - max_msg)) + 2
 */
static void uct_cxi_iface_size_tag_ring(uct_cxi_iface_t *self,
                                        const uct_cxi_iface_config_t *config,
                                        size_t outstanding)
{
    size_t max_msg  = self->tag.max_msg;
    size_t min_size = 2 * max_msg;
    size_t buf_size;
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
            ucs_warn("cxi TAG_OVERFLOW_BUF_SIZE %zu is too small for %zu-byte "
                     "messages: using %zu",
                     buf_size, max_msg, min_size);
        }
        buf_size = min_size;
    }

    needed = outstanding / (buf_size - max_msg) + 2;

    if (config->tag_ovf_num_bufs == UCS_ULUNITS_AUTO) {
        num_bufs = needed;
    } else {
        num_bufs = config->tag_ovf_num_bufs;
        if (needed > num_bufs) {
            ucs_warn("cxi TAG_OVERFLOW_NUM_BUFS %lu is below the %lu that "
                     "FC_ACTIVE_SENDERS peers at their full window need: the "
                     "ring can run out of buffers under load",
                     num_bufs, needed);
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
    struct cxi_pt_alloc_opts pt_opts = {
        .is_matching    = 1,
        .use_long_event = 1,
        .en_flowctrl    = 1
    };
    ucs_mpool_params_t mp_params;
    ucs_status_t status;
    size_t total;
    unsigned i;
    int ret;

    memset(&self->tag, 0, sizeof(self->tag));
    self->tag.ptn = -1;

    if (!uct_cxi_iface_tag_requested(config, params)) {
        /*
         * No HW tag offload (no unexpected callbacks from UCP, or forced off):
         * tag.pte stays NULL and UCP matches in software over AM.
         */
        return UCS_OK;
    }

    self->tag.eager_cb  = params->eager_cb;
    self->tag.eager_arg = params->eager_arg;
    self->tag.rndv_cb   = params->rndv_cb;
    self->tag.rndv_arg  = params->rndv_arg;

    /*
     * Leaves the two buffer_ids of SEARCH_AND_DELETE and the fences below
     * 65535.
     */
    self->tag.max_outstanding = ucs_min(config->tag_max_outstanding,
                                        UCT_CXI_TAG_MAX_OUTSTANDING_MAX);

    /*
     * A buffer of twice min_free (the largest message) holds one message before
     * retiring.
     */
    self->tag.max_msg = uct_cxi_tag_max_msg(config);
    if (self->tag.max_msg < config->tag_eager_max) {
        ucs_warn("cxi TAG_EAGER_MAX %zu exceeds the %u bytes that min_free can "
                 "express: limiting the eager size to it",
                 config->tag_eager_max, UCT_CXI_AM_MAX_MSG_LIMIT);
    }
    uct_cxi_iface_size_tag_ring(self, config, byte_credits);

    /*
     * Unexpected messages at once: bounded by the windows (an eager message's
     * slots each) and, if small, by a receive per message.
     */
    self->tag.unexp_max = ucs_max(self->tag.max_outstanding,
                                  slot_credits / UCT_CXI_FC_SLOTS_TAG_EAGER);
    if (self->tag.unexp_max > UCT_CXI_TAG_UNEXP_MAX_LIMIT) {
        ucs_warn("cxi tag wants room for %zu unexpected messages, limited to "
                 "%u",
                 self->tag.unexp_max, UCT_CXI_TAG_UNEXP_MAX_LIMIT);
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
    self->tag.pend = ucs_calloc(UCT_CXI_TAG_PEND_SIZE, sizeof(*self->tag.pend),
                                "cxi-tag-pend");
    self->tag.slot_pos = ucs_calloc(self->tag.max_outstanding,
                                    sizeof(*self->tag.slot_pos),
                                    "cxi-tag-slot-pos");

    self->tag.fences = ucs_calloc(UCT_CXI_TAG_PEND_SIZE,
                                  sizeof(*self->tag.fences), "cxi-tag-fences");
    if ((self->tag.pend == NULL) || (self->tag.slot_pos == NULL) ||
        (self->tag.fences == NULL)) {
        status = UCS_ERR_NO_MEMORY;
        goto err_free_pend;
    }
    self->tag.fence_interval = ucs_max(config->tag_fence_interval, 1u);

    /* Per-peer unexpected-rndv header cache (uct_cxi_rndv_peer_hdr_t). */
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
    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_rdzv_get_op_t);
    mp_params.elems_per_chunk = ucs_max(ucs_min(64u, self->tag.max_outstanding),
                                        1u);
    mp_params.max_elems       = self->tag.max_outstanding;
    mp_params.ops             = &uct_cxi_host_mpool_ops;
    mp_params.name            = "cxi-tag-rdzv-get-op";
    status = ucs_mpool_init(&mp_params, &self->tag.rdzv_get_op_pool);
    if (status != UCS_OK) {
        goto err_free_rndv_peer_cache;
    }

    status = uct_cxi_iface_tag_unexp_init(self, lni);
    if (status != UCS_OK) {
        goto err_cleanup_rdzv_get_op_pool;
    }

    /* Overflow ring: one allocation, one cxil_map, as for the AM ring. */
    total = (size_t)self->tag.num_bufs * self->tag.buf_size;
    ret   = ucs_posix_memalign((void**)&self->tag.rx_base, ucs_get_page_size(),
                               total, "cxi-tag-rx-buf");
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

    /* One ref-count/repost-pending slot per overflow buffer. */
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

    ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts, &self->tag.pte);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte tag: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_rx;
    }
    self->tag.ptn = self->tag.pte->ptn;
    uct_cxi_iface_tag_init_recv_le(self);

    ret = cxil_map_pte(self->tag.pte, self->domain, (int)UCT_CXI_PTE_TAG, false,
                       &self->tag.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte tag: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pte;
    }

    status = uct_cxi_iface_pte_enable(self, self->tag.pte, &self->rx_eq);
    if (status != UCS_OK) {
        goto err_unmap_pte;
    }

    /* Priority LEs are posted per uct_iface_tag_recv_zcopy(), not up front. */
    for (i = 0; i < self->tag.num_bufs; i++) {
        status = uct_cxi_iface_post_tag_ovf_le(self, (int)i, 0);
        if (status != UCS_OK) {
            goto err_unmap_pte;
        }
    }

    self->tag.enabled = 1;
    ucs_debug("cxi tag ring: %u buffers of %zu bytes, min_free %zu; %zu "
              "unexpected messages, %u posted receives",
              self->tag.num_bufs, self->tag.buf_size, self->tag.max_msg,
              self->tag.unexp_max, self->tag.max_outstanding);
    ucs_debug("cxi tag PTE ptn %u enabled", self->tag.pte->ptn);
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
            ucs_warn("cxi cxil_unmap_pte tag failed: %s", strerror(-ret));
        }
    }
    if (self->tag.pte != NULL) {
        ret = cxil_destroy_pte(self->tag.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte tag failed: %s", strerror(-ret));
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


/*
 * The address table (iface->rdzv.addr_table): one registered slot per 8-bit
 * rendezvous id, in LAC 0 as the RMA PTE it is read through.
 */
static ucs_status_t
uct_cxi_iface_rdzv_table_init(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    size_t page = ucs_get_page_size();
    size_t len  = ucs_align_up(UCT_CXI_RDZV_MAX_OUTSTANDING_MAX *
                                       sizeof(uint64_t),
                               page);
    ucs_status_t status;
    int ret;

    ret = ucs_posix_memalign((void**)&self->rdzv.addr_table, page, len,
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
    self->rdzv.addr_table = NULL;
}

/*
 * Open the rendezvous source-exposure PTE: matching mode, one persistent
 * wildcard LE over the whole address range (as libfabric). Matching mode puts
 * the Get on the wire format with match_bits, for O(1) id correlation. Opened
 * only with tag offload.
 */
ucs_status_t
uct_cxi_iface_open_rdzv_pte(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    uct_cxi_md_t *md                 = uct_cxi_iface_md(self);
    struct cxi_pt_alloc_opts pt_opts = {
        .is_matching = 1,
        .en_flowctrl = 1
    };
    struct c_target_cmd le           = {};
    ucs_status_t status;
    uint32_t i;
    int ret;

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

    ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts, &self->rdzv.pte);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte rdzv: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_free_ids;
    }
    self->rdzv.ptn = self->rdzv.pte->ptn;

    /*
     * pid_idx must be the device's rdzv_get_idx: the NIC's auto-issued
     * rendezvous Get targets that fixed value.
     */
    ret = cxil_map_pte(self->rdzv.pte, self->domain,
                       (int)md->cxi_dev->info.rdzv_get_idx, false,
                       &self->rdzv.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte rdzv: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_pte;
    }

    status = uct_cxi_iface_pte_enable(self, self->rdzv.pte, &self->rx_eq);
    if (status != UCS_OK) {
        goto err_unmap_pte;
    }

    /* The whole-LAC catch-all LE: fully wildcarded and unrestricted-flavored,
     * as libfabric's default one. match_id must be ANY, as zero matches one
     * bogus initiator. */
    le.command.opcode       = C_CMD_TGT_APPEND;
    le.ptl_list             = C_PTL_LIST_PRIORITY;
    le.ptlte_index          = self->rdzv.pte->ptn;
    le.op_get               = 1;
    le.unrestricted_body_ro = 1;
    le.unrestricted_end_ro  = 1;
    le.event_link_disable   = 1;
    le.event_unlink_disable = 1;
    le.length               = (1ULL << 56) - 1;
    le.match_id             = CXI_MATCH_ID_ANY;
    le.ignore_bits          = UINT64_MAX;

    ret = cxi_cq_emit_target(self->tgt.cmdq, &le);
    if (ret != 0) {
        ucs_error("cxi rdzv append LE: %d", ret);
        status = UCS_ERR_IO_ERROR;
        goto err_unmap_pte;
    }
    cxi_cq_ring(self->tgt.cmdq);

    self->rdzv.enabled = 1;
    ucs_debug("cxi rdzv PTE ptn %u enabled", self->rdzv.pte->ptn);
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
            ucs_warn("cxi cxil_unmap_pte rdzv failed: %s", strerror(-ret));
        }
    }
    if (self->rdzv.pte != NULL) {
        ret = cxil_destroy_pte(self->rdzv.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte rdzv failed: %s", strerror(-ret));
        }
    }
    self->rdzv.ptn = -1;
    uct_cxi_iface_rdzv_table_cleanup(self);
    ucs_free(self->rdzv.free_ids);
    self->rdzv.free_ids = NULL;
    ucs_free(self->rdzv.ops);
    self->rdzv.ops = NULL;
}


/* Event dispatch, called from the progress loop in cxi_iface.c. */

/* Return the posted-receive \a slot to the free list. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_tag_slot_free(uct_cxi_iface_t *iface, int slot)
{
    iface->tag.ctx[slot]                          = NULL;
    iface->tag.free_list[iface->tag.free_count++] = (uint16_t)slot;
}

/* Locate the overflow buffer and the data pointer for an event's
 * tgt_long.start, for events that carry only an address (a delayed match, or an
 * arrival reported later from a copy of its event). */
static inline int
uct_cxi_iface_tag_ovf_buf_idx(uct_cxi_iface_t *iface, uint64_t start)
{
    uint64_t base_iova = uct_cxi_mem_iova(&iface->tag.rx_mh,
                                          iface->tag.rx_base);

    return (int)((start - base_iova) / iface->tag.buf_size);
}

static inline void *
uct_cxi_iface_tag_ovf_data(uct_cxi_iface_t *iface, int buf_idx, uint64_t start)
{
    uint8_t *buf_va   = iface->tag.rx_base +
                        (size_t)buf_idx * iface->tag.buf_size;
    uint64_t buf_iova = uct_cxi_mem_iova(&iface->tag.rx_mh, buf_va);

    return buf_va + (size_t)(start - buf_iova);
}

/*
 * Repost this buffer generation once its refcnt reads 0 and a repost is
 * pending. Also checked from the increment side: a decrement can land before
 * its increment (seen on hardware).
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
 * Drop one reference on an overflow buffer generation (ovf_refcnt), when the
 * resolving event had mlength > 0, from the handler that reads that arrival's
 * payload. No assert that refcnt > 0: a decrement can land before its
 * increment, so refcnt is signed.
 */
static inline void
uct_cxi_iface_tag_ovf_release(uct_cxi_iface_t *iface, int buf_idx)
{
    iface->tag.ovf_refcnt[buf_idx]--;
    uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
}

/*
 * Return the credits \a initiator was charged for a message that went to the
 * overflow list: \a slots and the buffer space of its \a length bytes as sent.
 * A sender without flow control was charged nothing; a message that matched a
 * posted receive is never tracked.
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
 * reference (\a buf_idx, -1 if none) and return its sender's credits, in that
 * order so the credit is never back before the buffer can be reused.
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
 * from the event of its arrival or a copy of it: at once, or later behind an
 * unexpected rendezvous of the same sender. eager_cb (rndv_cb for a request)
 * gets the message in place in the overflow buffer, with this arrival's
 * reference held during the call and released after, with the sender's credits.
 */
static void uct_cxi_iface_tag_report_unexp_eager(uct_cxi_iface_t *iface,
                                                 const union c_event *event)
{
    uint32_t len       = event->tgt_long.mlength;
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    uint32_t sent_len  = event->tgt_long.rlength;
    uint64_t tag       = event->tgt_long.match_bits;
    uint64_t imm       = event->tgt_long.header_data;
    void *context      = NULL;
    void *data;
    int buf_idx;

    /*
     * Find the buffer from where the message sits, not the command's buffer_id:
     * the SEARCH_AND_DELETE took the oldest entry with this tag, which need not
     * be this arrival.
     */
    buf_idx = (len > 0) ? uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                        event->tgt_long.start) :
                          -1;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        /*
         * Not expected with use_once 1: release the reference but return no
         * credits, as the message still on the list will.
         */
        ucs_error("cxi tag search delete unexpected rc tag 0x%lx rc %d "
                  "buf_idx %d: C_EVENT_PUT_OVERFLOW with use_once 1 "
                  "reported a non-OK rc, which real-hardware testing never "
                  "observed; releasing anyway",
                  (unsigned long)tag, cxi_event_rc(event), buf_idx);
        if (len > 0) {
            uct_cxi_iface_tag_ovf_release(iface, buf_idx);
        }
        return;
    }

    ucs_trace("cxi tag search delete match tag 0x%lx len %u buf_idx %d",
              (unsigned long)tag, len, buf_idx);

    /*
     * Hand the payload to UCP in place; without UCT_CB_PARAM_FLAG_DESC it
     * copies what it keeps. The reference is held so no repost can overwrite it
     * even if the callback re-enters progress. Do not read \a event after the
     * call: its slot may be recycled.
     */
    data = (len > 0) ? uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                  event->tgt_long.start) :
                       NULL;
    if (imm == UCT_CXI_TAG_SW_RNDV_IMM) {
        /* A software rendezvous request: UCP's RTS is the payload, with no
         * remote address. */
        (void)iface->tag.rndv_cb(iface->tag.rndv_arg, 0, tag, data, len, 0, 0,
                                 NULL);
    } else {
        (void)iface->tag.eager_cb(iface->tag.eager_arg, data, len,
                                  UCT_CB_PARAM_FLAG_FIRST, tag, imm, &context);
    }

    /* Copied out by the callback: the sender's credits are free to go back. */
    uct_cxi_tag_ovf_done(iface, buf_idx, initiator, sent_len);
}

/*
 * Posted receives that can still take an unexpected message
 * (uct_cxi_tag_pend_t).
 */

#define UCT_CXI_TAG_PEND_MASK (UCT_CXI_TAG_PEND_SIZE - 1u)

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
    uint32_t pos = iface->tag.slot_pos[slot];
    uct_cxi_tag_pend_t *e;
    unsigned prev;

    if (!uct_cxi_tag_pend_in_window(iface, pos)) {
        return UCT_CXI_TAG_PEND_FREE;
    }

    e        = &iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK];
    prev     = e->state;
    e->state = UCT_CXI_TAG_PEND_SPENT;
    return prev;
}

/*
 * A message with \a tag arrived in the overflow list and no receive has matched
 * it yet. Hardware gives it to the first receive appended after it landed whose
 * tag matches, so the first matching PENDING receive in the ring is claimed.
 * UCP is told it is taken now (tag_consumed_cb), before it could match that
 * receive to another message; the match event finds UCT_CXI_TAG_FLAG_CONSUMED.
 * Returns 1 if a receive was claimed.
 */
static int uct_cxi_tag_claim(uct_cxi_iface_t *iface, uint64_t tag)
{
    uint32_t n;
    uct_cxi_tag_pend_t *e;
    uct_tag_context_t *ctx;
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
        priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;
        ucs_assert(!(priv->rndv_flags & UCT_CXI_TAG_FLAG_CONSUMED));

        e->state          = UCT_CXI_TAG_PEND_CLAIMED;
        priv->rndv_flags |= UCT_CXI_TAG_FLAG_CONSUMED;
        ucs_trace("cxi tag claim tag 0x%lx by slot %u (pos %u)",
                  (unsigned long)tag, (unsigned)e->slot, n);
        ctx->tag_consumed_cb(ctx);
        return 1;
    }

    return 0;
}

/*
 * Post a fence: a search that matches nothing (as libfabric's
 * cxip_flush_appends()). The command queue is in order, so its event follows
 * those of every earlier append; the ring's window moves up to it then
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
        ucs_error("cxi tag a fence event with no fence in flight, rc %d",
                  cxi_event_rc(event));
        return;
    }

    iface->tag.pend_tail =
            iface->tag.fences[iface->tag.fence_tail++ & UCT_CXI_TAG_PEND_MASK];
}

/* Held unexpected reports (uct_cxi_unexp_report_t in cxi_tag.h). */

static void uct_cxi_unexp_read_comp(uct_cxi_send_op_t *op, ucs_status_t status);
static void uct_cxi_tag_found_eager(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint64_t seq);

/* The stream of \a initiator's messages with \a tag, NULL if none of them is
 * held. */
static uct_cxi_unexp_stream_t *uct_cxi_unexp_stream_find(uct_cxi_iface_t *iface,
                                                         uint32_t initiator,
                                                         uint64_t tag)
{
    uct_cxi_unexp_key_t key = {};
    khiter_t k;

    key.tag       = tag;
    key.initiator = initiator;
    k = kh_get(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, key);
    return (k == kh_end(&iface->tag.unexp_streams)) ?
                   NULL :
                   kh_value(&iface->tag.unexp_streams, k);
}

/* As above, making the stream if there is none. NULL if all are in use. */
static uct_cxi_unexp_stream_t *uct_cxi_unexp_stream_get(uct_cxi_iface_t *iface,
                                                        uint32_t initiator,
                                                        uint64_t tag)
{
    uct_cxi_unexp_stream_t *stream = uct_cxi_unexp_stream_find(iface, initiator,
                                                               tag);
    uct_cxi_unexp_key_t key        = {};
    khiter_t k;
    int ret;

    if (stream != NULL) {
        return stream;
    }

    stream = iface->tag.unexp_stream_free;
    if (stream == NULL) {
        return NULL;
    }

    key.tag       = tag;
    key.initiator = initiator;
    k = kh_put(uct_cxi_unexp_stream_hash, &iface->tag.unexp_streams, key, &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        return NULL;
    }

    iface->tag.unexp_stream_free           = stream->next_free;
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
static void
uct_cxi_unexp_stream_put(uct_cxi_iface_t *iface, uct_cxi_unexp_stream_t *stream)
{
    uct_cxi_unexp_key_t key = {};
    khiter_t k;

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

/*
 * Take an entry for \a event and chain it in its stream where its arrival
 * number \a seq puts it: at the end unless a later arrival already has an
 * entry. NULL if all entries or streams are in use.
 */
static uct_cxi_unexp_report_t *
uct_cxi_unexp_alloc(uct_cxi_iface_t *iface, const union c_event *event,
                    int is_rndv, uint8_t flags, uint64_t seq)
{
    ucs_list_link_t *pos;
    uct_cxi_unexp_report_t *e = iface->tag.unexp_free;
    uct_cxi_unexp_stream_t *stream;

    if (e == NULL) {
        return NULL;
    }

    stream = uct_cxi_unexp_stream_get(
            iface, event->tgt_long.initiator.initiator.process,
            event->tgt_long.match_bits);
    if (stream == NULL) {
        return NULL;
    }

    iface->tag.unexp_free = e->next_free;
    uct_cxi_send_op_set(&e->op, NULL, NULL, uct_cxi_unexp_read_comp);
    e->iface         = iface;
    e->event         = *event;
    e->stream        = stream;
    e->initiator     = stream->initiator;
    e->tag           = stream->tag;
    e->rendezvous_id = event->tgt_long.rendezvous_id;
    e->is_rndv       = is_rndv;
    e->state         = is_rndv ? UCT_CXI_UNEXP_NEW : UCT_CXI_UNEXP_READY;
    e->flags         = flags;
    e->value         = 0;
    e->seq           = seq;
    ucs_list_head_init(&e->wait);
    pos = stream->entries.prev;
    while ((pos != &stream->entries) &&
           (ucs_container_of(pos, uct_cxi_unexp_report_t, link)->seq > seq)) {
        pos = pos->prev;
    }
    ucs_list_insert_after(pos, &e->link);
    stream->num_lost      += !!(flags & UCT_CXI_UNEXP_LOST);
    iface->tag.unexp_held += is_rndv;
    return e;
}

/* Take an entry off its chain; it is not free until uct_cxi_unexp_free(), and
 * its stream, if now empty, is the caller's to give back. */
static void
uct_cxi_unexp_unlink(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
{
    ucs_list_del(&e->link);
    e->stream->num_lost   -= !!(e->flags & UCT_CXI_UNEXP_LOST);
    iface->tag.unexp_held -= e->is_rndv;
    if (!ucs_list_is_empty(&e->wait)) {
        ucs_list_del(&e->wait);
        ucs_list_head_init(&e->wait);
    }
}

/*
 * Give back an entry that is off its chain. For a rendezvous this is where the
 * sender's credits go back, once: every way out of the table ends here.
 */
static void
uct_cxi_unexp_free(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
{
    if (e->is_rndv) {
        uct_cxi_tag_credit_return(iface, e->initiator,
                                  UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
    }

    e->next_free          = iface->tag.unexp_free;
    iface->tag.unexp_free = e;
}

/*
 * An entry with nothing to wait for or report (a tombstone whose message
 * arrived, or one that could not be handed on): its address read is not posted.
 */
static void
uct_cxi_unexp_discard(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
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
static int uct_cxi_unexp_has_older(uct_cxi_unexp_stream_t *stream, uint64_t seq)
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
 * endpoint would use (LAC 0, pid_offset 0). Waits only for command queue room.
 * The REPLY is on the RX queue like other handler-issued Gets. UCS_ERR_NO_ELEM:
 * its announce has not been seen.
 */
static ucs_status_t
uct_cxi_unexp_start_read(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
{
    uct_cxi_md_t *md = uct_cxi_iface_md(iface);
    khiter_t k = kh_get(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache,
                        e->initiator);
    const uct_cxi_rndv_peer_hdr_t *peer;
    struct c_full_dma_cmd cmd = {};
    union c_fab_addr dfa;
    uint8_t idx_ext;
    ucs_time_t deadline;
    int ret;

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
    cmd.local_addr  = uct_cxi_mem_iova(&iface->tag.unexp_ents_mh, &e->value);
    cmd.request_len = sizeof(e->value);
    cmd.user_ptr    = (uint64_t)(uintptr_t)e;

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
static void
uct_cxi_unexp_start(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
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
        ucs_error("cxi tag cannot read the source address of an unexpected "
                  "rendezvous: %s",
                  ucs_status_string(status));
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
 * Report \a e, which is off its stream's chain, to UCP and give it back,
 * released first and reported from copies as the callback may re-enter
 * progress. For a rendezvous, rndv_cb gets the sender's cached {ep_id,
 * md_index} plus the message's req_id as header, the source address read from
 * the sender's table, and a stack uct_cxi_rkey_t (is_rndv, rendezvous_id) that
 * lets UCP's later get reach the sender's rendezvous PTE. flags=0, as
 * uct_rc_mlx5_handle_unexp_rndv().
 */
static void
uct_cxi_unexp_report(uct_cxi_iface_t *iface, uct_cxi_unexp_report_t *e)
{
    union c_event event = e->event;
    uint64_t addr       = e->value;
    int is_rndv         = e->is_rndv;
    int failed          = (e->state == UCT_CXI_UNEXP_FAILED);
    uct_cxi_rndv_hdr_wire_t hdr;
    uct_cxi_rkey_t rkey = {};
    khiter_t k;

    uct_cxi_unexp_free(iface, e);

    if (!is_rndv) {
        uct_cxi_iface_tag_report_unexp_eager(iface, &event);
        return;
    }

    if (failed) {
        ucs_error("cxi tag unexpected rendezvous tag 0x%lx dropped: the "
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

    ucs_trace("cxi tag rndv report tag 0x%lx rlength %u rendezvous_id %u "
              "addr 0x%lx",
              (unsigned long)event.tgt_long.match_bits,
              (unsigned)event.tgt_long.rlength, (unsigned)rkey.rendezvous_id,
              (unsigned long)addr);

    (void)iface->tag.rndv_cb(iface->tag.rndv_arg, 0, event.tgt_long.match_bits,
                             &hdr, sizeof(hdr), addr, event.tgt_long.rlength,
                             &rkey);
}

/*
 * Report what can be of \a stream, in order: the entry at the head of its chain
 * if ready, then the next, until one is not. A report can re-enter progress, so
 * while busy the stream is not advanced or given back; this loop picks up what
 * the events did.
 */
static void
uct_cxi_unexp_advance(uct_cxi_iface_t *iface, uct_cxi_unexp_stream_t *stream)
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
    uct_cxi_unexp_report_t *e = (uct_cxi_unexp_report_t*)op;

    e->state = (status == UCS_OK) ? UCT_CXI_UNEXP_READY : UCT_CXI_UNEXP_FAILED;
    ucs_assert(!(e->flags & UCT_CXI_UNEXP_LOST));
    uct_cxi_unexp_advance(e->iface, e->stream);
}

/*
 * The announce of \a initiator has been seen: post the address reads of its
 * waiting rendezvous, rescanning after each as a failed read is reported.
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

/*
 * The delayed match of message \a event (a rendezvous, or an eager message
 * without data) came before the message was seen: leave a tombstone for the
 * arrival; \a flags are added to UCT_CXI_UNEXP_LOST.
 */
static void uct_cxi_unexp_tombstone(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint8_t flags)
{
    ucs_trace("cxi tag unexp lost first tag 0x%lx id %u: claimed before it "
              "was seen arriving",
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rendezvous_id);
    if (ucs_unlikely(uct_cxi_unexp_alloc(iface, event,
                                         event->tgt_long.rendezvous,
                                         UCT_CXI_UNEXP_LOST | flags,
                                         iface->tag.unexp_seq++) == NULL)) {
        ucs_error("cxi tag no free entry to note a message claimed by a "
                  "receive, tag 0x%lx initiator 0x%x",
                  (unsigned long)event->tgt_long.match_bits,
                  (unsigned)event->tgt_long.initiator.initiator.process);
    }
}

/*
 * The arrival of a rendezvous or an eager message without data is handled. If
 * its receive's match came first there is a tombstone and the message is that
 * receive's (unless UCT_CXI_UNEXP_REDELIVER, which is reported now). Returns 1
 * if there was one.
 */
static int uct_cxi_unexp_arrival_lost(uct_cxi_iface_t *iface,
                                      const union c_event *event, uint64_t seq)
{
    uct_cxi_unexp_stream_t *stream = uct_cxi_unexp_stream_find(
            iface, event->tgt_long.initiator.initiator.process,
            event->tgt_long.match_bits);
    uint8_t is_rndv                = event->tgt_long.rendezvous;
    uint8_t id                     = event->tgt_long.rendezvous_id;
    uct_cxi_unexp_report_t *e;
    int redeliver;
    union c_event copy;

    if ((stream == NULL) || (stream->num_lost == 0)) {
        return 0;
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
    uct_cxi_unexp_discard(iface, e);
    if (redeliver) {
        /* The report may re-enter progress, so it gets a copy. */
        copy = *event;
        uct_cxi_tag_found_eager(iface, &copy, seq);
    }
    uct_cxi_unexp_advance(iface, stream);
    return 1;
}

/* Pairing the two events of an unexpected eager message. */

static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
                                             const union c_event *event,
                                             uint64_t seq);

/*
 * A delayed match of an eager message with data may only proceed once the
 * message's arrival has been seen (the Put is written after the data;
 * uct_cxi_eager_pair_t). Returns 1 with the arrival number in *seq_p; if not,
 * the event is kept for uct_cxi_eager_take_parked() and 0 is returned.
 */
static int uct_cxi_eager_match_ready(uct_cxi_iface_t *iface,
                                     const union c_event *event,
                                     uint64_t *seq_p)
{
    uct_cxi_eager_pair_t *pair;
    khiter_t k;
    int ret;

    k = kh_get(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start);
    if (k != kh_end(&iface->tag.eager_pairs)) {
        pair = &kh_value(&iface->tag.eager_pairs, k);
        if (ucs_likely(!pair->parked)) {
            *seq_p = pair->seq;
            kh_del(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs, k);
            return 1;
        }
        ucs_error("cxi tag a second match for the unexpected eager message "
                  "at 0x%lx",
                  (unsigned long)event->tgt_long.start);
        return 0;
    }

    k = kh_put(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start, &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi tag cannot wait for the arrival of the unexpected "
                  "eager message at 0x%lx: out of memory",
                  (unsigned long)event->tgt_long.start);
        *seq_p = iface->tag.unexp_seq++;
        return 1;
    }

    pair         = &kh_value(&iface->tag.eager_pairs, k);
    pair->parked = 1;
    pair->event  = *event;
    ucs_trace("cxi tag eager match early start 0x%lx delayed match before "
              "its arrival",
              (unsigned long)event->tgt_long.start);
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
    khiter_t k;

    k = kh_get(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start);
    if (k == kh_end(&iface->tag.eager_pairs)) {
        return 0;
    }

    pair = kh_value(&iface->tag.eager_pairs, k);
    if (!pair.parked) {
        ucs_error("cxi tag a second arrival of the unexpected eager message "
                  "at 0x%lx",
                  (unsigned long)event->tgt_long.start);
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
    int ret;

    k = kh_put(uct_cxi_eager_pair_hash, &iface->tag.eager_pairs,
               event->tgt_long.start, &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi tag cannot note the arrival of the unexpected eager "
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
 * is still held: UCP must hear of that first. One load when no rendezvous is
 * held.
 */
static void uct_cxi_tag_found_eager(uct_cxi_iface_t *iface,
                                    const union c_event *event, uint64_t seq)
{
    if (ucs_unlikely(iface->tag.unexp_held != 0) &&
        (cxi_event_rc(event) == C_RC_OK)) {
        uct_cxi_unexp_stream_t *stream = uct_cxi_unexp_stream_find(
                iface, event->tgt_long.initiator.initiator.process,
                event->tgt_long.match_bits);

        if ((stream != NULL) && uct_cxi_unexp_has_older(stream, seq)) {
            if (uct_cxi_unexp_alloc(iface, event, 0, 0, seq) != NULL) {
                return;
            }
            ucs_warn("cxi tag no free entry to hold an unexpected eager "
                     "message behind an unexpected rendezvous: reporting it "
                     "out of order");
        }
    }

    uct_cxi_iface_tag_report_unexp_eager(iface, event);
}

/*
 * The outcome of a SEARCH_AND_DELETE that found a message: nothing to do, as it
 * was handed to UCP on arrival and its reference and credits go back when it is
 * reported. It is the oldest with the tag, which the command was issued for.
 */
void uct_cxi_iface_tag_handle_search_delete_found(uct_cxi_iface_t *iface,
                                                  const union c_event *event)
{
    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        ucs_error("cxi tag search delete unexpected rc tag 0x%lx rc %d",
                  (unsigned long)event->tgt_long.match_bits,
                  cxi_event_rc(event));
        return;
    }

    ucs_trace("cxi tag search delete found tag 0x%lx rlength %u rndv %u",
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rlength,
              (unsigned)event->tgt_long.rendezvous);
}

/*
 * A SEARCH_AND_DELETE found nothing: a receive appended before it took the
 * message, yet it was in the ring at arrival and would have been claimed. The
 * ring is wrong and UCP was given a message a receive also has.
 */
void uct_cxi_iface_tag_handle_search_delete_missed(uct_cxi_iface_t *iface,
                                                   const union c_event *event)
{
    ucs_error("cxi tag search delete not found rc %d: a message handed to "
              "UCP was taken by a posted receive as well",
              cxi_event_rc(event));
}

/*
 * Handler for the announce sent by uct_cxi_ep_send_rndv_hdr_announce(),
 * dispatched before uct_iface_invoke_am(). Fills iface->tag.rndv_peer_cache for
 * this initiator, then lets its waiting unexpected rendezvous go on.
 */
void uct_cxi_iface_handle_rndv_hdr_announce(uct_cxi_iface_t *iface,
                                            const union c_event *event,
                                            const void *payload, uint32_t len)
{
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    const uct_cxi_rndv_peer_hdr_t *hdr = payload;
    khiter_t k;
    int ret;

    if (ucs_unlikely(len != sizeof(*hdr))) {
        ucs_error("cxi tag rndv hdr announce bad length %u, expected %zu", len,
                  sizeof(*hdr));
        return;
    }

    k = kh_put(uct_cxi_rndv_peer_hash, &iface->tag.rndv_peer_cache, initiator,
               &ret);
    if (ucs_unlikely(ret == UCS_KH_PUT_FAILED)) {
        ucs_error("cxi tag rndv hdr announce rndv_peer_cache insert "
                  "failed, initiator 0x%x",
                  initiator);
        return;
    }
    kh_value(&iface->tag.rndv_peer_cache, k) = *hdr;

    ucs_debug("cxi tag rndv hdr announce initiator 0x%x ep_id 0x%lx "
              "md_index %u table_iova 0x%lx",
              initiator, (unsigned long)hdr->ep_id, (unsigned)hdr->md_index,
              (unsigned long)hdr->table_iova);

    uct_cxi_unexp_announced(iface, initiator);
}

/*
 * A Put the NIC could not place in an overflow buffer: no message, so nothing
 * to hand on or give back (the sender takes its credits back from the ACK).
 * Usually a message longer than what is left of its buffer; min_free prevents
 * that.
 */
static UCS_F_NOINLINE void
uct_cxi_iface_tag_ovf_failed(uct_cxi_iface_t *iface, const union c_event *event)
{
    int buf_idx = (int)event->tgt_long.buffer_id;

    ucs_error("cxi tag overflow Put failed: rc %d buf %d tag 0x%lx "
              "rlength %u mlength %u, message dropped",
              (int)cxi_event_rc(event), buf_idx,
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rlength,
              (unsigned)event->tgt_long.mlength);

    /* The buffer's fate does not depend on how this Put went. */
    if (event->tgt_long.auto_unlinked) {
        iface->tag.ovf_repost_pending[buf_idx] = 1;
        uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
    }
}

/*
 * An unexpected message landed in the overflow ring (C_EVENT_PUT, OVERFLOW).
 * Takes a reference on the buffer generation if mlength > 0 (ovf_refcnt) and
 * decides at once whose the message is, in landing order:
 *
 *   1. A receive's delayed match was seen first (parked, or a tombstone): the
 *      message is that receive's.
 *   2. A receive appended after it landed will take it: the first matching one
 *      in the ring (uct_cxi_tag_claim()) is claimed, UCP told it is taken, and
 *      its delayed match completes it.
 *   3. Otherwise it is UCP's: a SEARCH_AND_DELETE takes it off the NIC's list
 *      and it is reported at once.
 *
 * Reporting only after the command found the message left a window for the
 * tag_bw hang.
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    int buf_idx               = (int)event->tgt_long.buffer_id;
    uint64_t tag              = event->tgt_long.match_bits;
    uint64_t seq              = iface->tag.unexp_seq++;
    int is_rndv               = event->tgt_long.rendezvous;
    int has_data              = (event->tgt_long.mlength > 0);
    uct_cxi_unexp_report_t *e = NULL;
    struct c_target_cmd sd    = {};
    ucs_status_t status;

    if (ucs_unlikely(cxi_event_rc(event) != C_RC_OK)) {
        uct_cxi_iface_tag_ovf_failed(iface, event);
        return;
    }

    if (has_data) {
        iface->tag.ovf_refcnt[buf_idx]++;
        /* Checked here too: see uct_cxi_iface_tag_ovf_maybe_repost(). */
        uct_cxi_iface_tag_ovf_maybe_repost(iface, buf_idx);
    }
    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        /*
         * EQ delivery is ordered, so this is the generation's last Put: a
         * repost is owed once every message in it is resolved.
         */
        iface->tag.ovf_repost_pending[buf_idx] = 1;
    }

    ucs_trace("cxi tag ovf arrival buf_idx %d tag 0x%lx mlength %u "
              "rlength %u start 0x%lx auto_unlinked %u",
              buf_idx, (unsigned long)tag, (unsigned)event->tgt_long.mlength,
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

    /*
     * 2. A receive is to take it. A rendezvous's event-slot charge goes back
     * now; an eager message's goes back with its buffer, when the match has
     * copied it.
     */
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

    /*
     * 3. It is UCP's. A rendezvous is held for its address read, an eager
     * message reported at once. The entry is taken first: with none, the
     * message stays on the NIC's list.
     */
    if (is_rndv) {
        e = uct_cxi_unexp_alloc(iface, event, 1, 0, seq);
        if (ucs_unlikely(e == NULL)) {
            ucs_error("cxi tag no free entry to hold an unexpected "
                      "rendezvous, tag 0x%lx initiator 0x%x: not reported "
                      "unless a receive claims it",
                      (unsigned long)tag,
                      (unsigned)event->tgt_long.initiator.initiator.process);
            return;
        }
    }

    /*
     * Targets C_PTL_LIST_UNEXPECTED (as libfabric's SEARCH calls), match_id ANY
     * and a non-zero length (zero gave C_RC_NO_SPACE). use_once=1 gives exactly
     * one event: PUT_OVERFLOW if a message was deleted, SEARCH (C_RC_NO_MATCH)
     * if not.
     */
    sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
    sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
    sd.ptlte_index    = iface->tag.ptn;
    sd.match_bits     = tag;
    sd.match_id       = CXI_MATCH_ID_ANY;
    sd.length         = -1U;
    sd.use_once       = 1;
    sd.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID;

    /*
     * If the command queue stays wedged the message is not handed to UCP: it
     * stays on the NIC's list for whatever claims it later, with its reference
     * and credits.
     */
    status = uct_cxi_iface_tgt_post(iface, &sd);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi tag SEARCH_AND_DELETE post failed: %s: unexpected "
                  "message tag 0x%lx is not reported unless a receive claims "
                  "it",
                  ucs_status_string(status), (unsigned long)tag);
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
 * Software-issued pull for a direct-matched rendezvous receive: an unrestricted
 * DMA Get to the sender's rendezvous source PTE at the device's rdzv_get_idx
 * (restricted does not work, see uct_cxi_rdzv_op_t), addressed from the event's
 * initiator. cmd.match_bits is the sender's rendezvous id and local_addr the
 * destination buffer: the full [0, rlength) is fetched, as a rendezvous Put
 * never eager-attaches. user_ptr is a uct_cxi_rdzv_get_op_t, so the REPLY
 * completes through op->handler.
 */
static ucs_status_t
uct_cxi_iface_issue_rdzv_get(uct_cxi_iface_t *iface, const union c_event *event,
                             uint16_t slot, uint32_t posted_len)
{
    uct_cxi_md_t *md          = uct_cxi_iface_md(iface);
    uint32_t init_dfa         = event->tgt_long.initiator.initiator.process;
    struct c_full_dma_cmd cmd = {};
    uct_cxi_rdzv_get_op_t *rop;
    union c_fab_addr dfa;
    uint8_t idx_ext;
    int ret;

    rop = (uct_cxi_rdzv_get_op_t*)ucs_mpool_get(&iface->tag.rdzv_get_op_pool);
    if (ucs_unlikely(rop == NULL)) {
        ucs_error("cxi tag rdzv_get_op_pool exhausted, slot %u", slot);
        return UCS_ERR_NO_RESOURCE;
    }
    rop->op.ep      = NULL;
    rop->op.comp    = NULL;
    rop->op.handler = uct_cxi_rdzv_get_comp;
    rop->iface      = iface;
    rop->slot       = slot;

    /* pid_idx must be the sender's rdzv_get_idx, as for the NIC's own Get (see
     * uct_cxi_iface_open_rdzv_pte). */
    cxi_build_dfa(cxi_dfa_nid(init_dfa), cxi_dfa_pid(init_dfa, md->pid_bits),
                  md->pid_bits, md->cxi_dev->info.rdzv_get_idx, &dfa, &idx_ext);

    cmd.command.opcode     = C_CMD_GET;
    cmd.index_ext          = idx_ext;
    cmd.event_send_disable = 1;
    cmd.initiator          = iface->match_id;
    /* REPLY on the RX queue: a handler cannot be refused for a full TX queue,
     * and each posted receive has a slot budgeted for one. */
    cmd.eq                 = iface->rx_eq.evtq->eqn;
    cmd.dfa                = dfa;
    cmd.remote_offset      = event->tgt_long.remote_offset;
    cmd.local_addr         = event->tgt_long.start;
    /* The full [0, rlength) as a rendezvous Put never eager-attaches, clamped
     * to the posted buffer as libfabric does. */
    cmd.request_len        = ucs_min(posted_len, event->tgt_long.rlength);
    cmd.match_bits         = event->tgt_long.rendezvous_id;
    cmd.user_ptr           = (uint64_t)(uintptr_t)rop;

    ret = cxi_cq_emit_dma(iface->tx.cmdq, &cmd);
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(rop);
        ucs_error("cxi tag rdzv Get emit failed: %d slot %u", ret, slot);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ucs_trace("cxi tag rdzv get sw slot %u remote_offset 0x%lx "
              "local_addr 0x%lx len %u",
              slot, (unsigned long)event->tgt_long.remote_offset,
              (unsigned long)cmd.local_addr, cmd.request_len);
    return UCS_OK;
}

/*
 * The ctx lookup shared by the match handlers (the caller classifies eager vs
 * rendezvous). Returns the matched ctx with *slot_p set, or NULL for a stale or
 * resolved slot.
 */
static uct_tag_context_t *
uct_cxi_iface_tag_match_lookup(uct_cxi_iface_t *iface,
                               const union c_event *event, int *slot_p)
{
    int slot = (int)event->tgt_long.buffer_id;

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale event for a resolved slot (e.g. a force-cancel): drop it. */
        ucs_trace("cxi tag match stale slot %d already resolved, "
                  "dropping",
                  slot);
        return NULL;
    }

    *slot_p = slot;
    return iface->tag.ctx[slot];
}

/*
 * The receive a delayed match is for is gone (UCP assumed its cancel and
 * matched its message elsewhere) yet took the message: report it to UCP now as
 * unexpected. An eager message with data is whole in the ring (\a seq numbers
 * its arrival); one without has its arrival to come, so a tombstone is left.
 */
static void uct_cxi_tag_match_orphan(uct_cxi_iface_t *iface,
                                     const union c_event *event, uint64_t seq)
{
    union c_event copy;

    if (event->tgt_long.rlength == 0) {
        uct_cxi_unexp_tombstone(iface, event, UCT_CXI_UNEXP_REDELIVER);
        return;
    }

    ucs_debug("cxi tag match redeliver tag 0x%lx rlength %u: the receive was "
              "cancelled, reporting the message it took",
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.rlength);
    copy                  = *event;
    /* All of it is in the ring. */
    copy.tgt_long.mlength = event->tgt_long.rlength;
    uct_cxi_tag_found_eager(iface, &copy, seq);
}

/*
 * A plain eager match, direct (C_EVENT_PUT, PRIORITY) or delayed
 * (C_EVENT_PUT_OVERFLOW). Direct: the data was DMAed into the caller's buffer.
 * Delayed: the data landed in the overflow ring before this LE existed, so copy
 * it into priv->recv_addr (as libfabric's cxip_ux_send()), then release the
 * overflow reference and return the sender's credits. \a seq is the arrival
 * number, which matters only if the receive is gone. tag_consumed_cb is called
 * here unless the arrival already did.
 *
 * Checks cancel_ctx[slot].force before touching ctx/priv: if set, the slot is
 * reclaimed without reading ctx and the message is reported to UCP as
 * unexpected (uct_cxi_tag_match_orphan()).
 */
static void uct_cxi_tag_eager_match_complete(uct_cxi_iface_t *iface,
                                             const union c_event *event,
                                             uint64_t seq)
{
    int slot;
    uct_tag_context_t *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t stag;
    uint64_t imm;
    uint32_t mlength;
    ucs_status_t status;
    int buf_idx;
    unsigned prev = UCT_CXI_TAG_PEND_FREE;

    int delayed        = (event->hdr.event_type == C_EVENT_PUT_OVERFLOW);
    int has_data       = (event->tgt_long.rlength > 0);
    uint32_t initiator = event->tgt_long.initiator.initiator.process;
    uint32_t sent_len  = event->tgt_long.rlength;

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

    uct_cxi_tag_slot_free(iface, slot);

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        /* Force-cancelled: ctx is never read on this branch. */
        iface->tag.cancel_ctx[slot].force = 0;
        if (delayed) {
            uct_cxi_tag_match_orphan(iface, event, seq);
        }
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;

    ucs_trace("cxi eager tag %s slot %d tag 0x%lx mlength %u",
              delayed ? "ovf matched" : "direct match", slot,
              (unsigned long)event->tgt_long.match_bits,
              (unsigned)event->tgt_long.mlength);

    if (delayed) {
        /*
         * Delayed match: copy out of the overflow buffer, then release it and
         * return the credits. Gated on the message having data, as the
         * arrival's increment.
         */
        buf_idx = -1;
        if (has_data) {
            void *data;

            buf_idx = uct_cxi_iface_tag_ovf_buf_idx(iface,
                                                    event->tgt_long.start);
            data    = uct_cxi_iface_tag_ovf_data(iface, buf_idx,
                                                 event->tgt_long.start);
            memcpy((void*)(uintptr_t)priv->recv_addr, data,
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

    if (imm == UCT_CXI_TAG_SW_RNDV_IMM) {
        /*
         * A software rendezvous request: its payload, UCP's RTS, is in the
         * receive's buffer; UCP carries on from it. Truncated if the buffer was
         * too small.
         */
        ctx->rndv_cb(ctx, stag, (const void*)(uintptr_t)priv->recv_addr,
                     mlength, status, 0);
        return;
    }

    ctx->completed_cb(ctx, stag, imm, mlength, NULL, status);
}

/*
 * See uct_cxi_tag_eager_match_complete(). A delayed match with data waits for
 * the message's arrival event: the two come from different NIC pipelines.
 */
void uct_cxi_iface_tag_handle_eager_match(uct_cxi_iface_t *iface,
                                          const union c_event *event)
{
    uint64_t seq = 0;

    if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
        (event->tgt_long.rlength > 0) &&
        !uct_cxi_eager_match_ready(iface, event, &seq)) {
        /* Its arrival is yet to come: see uct_cxi_eager_take_parked(). */
        return;
    }

    uct_cxi_tag_eager_match_complete(iface, event, seq);
}

/*
 * OR seen_bit into a force-cancelled slot's cancel_ctx state and reclaim it
 * once UCT_CXI_RNDV_SEEN_REQUIRED is satisfied; other events of the transfer
 * may be in flight.
 */
static inline void uct_cxi_iface_tag_rdzv_cancel_seen(uct_cxi_iface_t *iface,
                                                      int slot,
                                                      uint8_t seen_bit)
{
    uint8_t seen = (iface->tag.cancel_ctx[slot].rndv_seen |= seen_bit);

    if ((seen & UCT_CXI_RNDV_SEEN_REQUIRED) == UCT_CXI_RNDV_SEEN_REQUIRED) {
        uct_cxi_tag_slot_free(iface, slot);
        iface->tag.cancel_ctx[slot].force = 0;
    }
}

/*
 * Fail a rendezvous receive now and leave its slot to the cancel_ctx deferred
 * reclaim, as if force-cancelled: other required events must drain before the
 * slot is reused.
 */
static void uct_cxi_iface_tag_rdzv_fail(uct_cxi_iface_t *iface,
                                        uct_tag_context_t *ctx, int slot,
                                        uint8_t seen_bit, ucs_status_t status)
{
    uct_cxi_tag_ctx_priv_t *priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;

    ctx->completed_cb(ctx, priv->stag, 0, 0, NULL, status);
    iface->tag.cancel_ctx[slot].rndv_seen = priv->rndv_flags;
    iface->tag.cancel_ctx[slot].force     = 1;
    uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
}

/*
 * A rendezvous match: C_EVENT_PUT/PUT_OVERFLOW with rendezvous == 1, or
 * C_EVENT_RENDEZVOUS itself. The receive completes once all of
 * UCT_CXI_RNDV_SEEN_REQUIRED has arrived: Put and Rendezvous in either order
 * (as libfabric), Reply only after Rendezvous. tag_consumed_cb fires on the
 * first event. Checks cancel_ctx[slot].force before touching ctx/priv.
 */
void uct_cxi_iface_tag_handle_rdzv_match(uct_cxi_iface_t *iface,
                                         const union c_event *event)
{
    int slot;
    uct_tag_context_t *ctx = uct_cxi_iface_tag_match_lookup(iface, event,
                                                            &slot);
    uct_cxi_tag_ctx_priv_t *priv;
    uint8_t seen_bit;
    uint64_t stag;
    uint32_t length;
    ucs_status_t status;

    if ((event->hdr.event_type != C_EVENT_RENDEZVOUS) &&
        ((unsigned)event->tgt_long.buffer_id < iface->tag.max_outstanding)) {
        unsigned prev = uct_cxi_tag_pend_spent(iface,
                                               event->tgt_long.buffer_id);

        if ((event->hdr.event_type == C_EVENT_PUT_OVERFLOW) &&
            (prev != UCT_CXI_TAG_PEND_CLAIMED)) {
            /*
             * The delayed match of a rendezvous that arrived unexpected came
             * first, whether or not the receive is still there: leave a note
             * for the arrival.
             */
            uct_cxi_unexp_tombstone(iface, event, 0);
        }
    }

    if (ctx == NULL) {
        return;
    }

    seen_bit = (event->hdr.event_type == C_EVENT_RENDEZVOUS) ?
                       UCT_CXI_RNDV_SEEN_RNDV :
                       UCT_CXI_RNDV_SEEN_PUT;

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
            /*
             * The buffer is gone (UCP's contract for force=1): never issue a
             * Get into it. The Reply is abandoned if no Get was issued, but
             * kept pending if the NIC's auto-Get is in flight.
             */
            ucs_trace("cxi tag rndv cancel slot %d get_issued %u", slot,
                      (unsigned)event->tgt_long.get_issued);
            if (!event->tgt_long.get_issued) {
                seen_bit |= UCT_CXI_RNDV_SEEN_REPLY;
            }
        }
        /*
         * No release here: mlength is 0 for a rendezvous arrival, so no
         * ovf_refcnt reference was taken.
         */
        uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
        return;
    }

    priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
                priv->slot, slot);

    if (!(priv->rndv_flags & UCT_CXI_RNDV_FLAG_IS_RNDV)) {
        /*
         * First of the three events: fire tag_consumed_cb now unless the
         * arrival already did.
         */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_IS_RNDV;
        if (!(priv->rndv_flags & UCT_CXI_TAG_FLAG_CONSUMED)) {
            ctx->tag_consumed_cb(ctx);
        }
    }

    if (event->hdr.event_type == C_EVENT_RENDEZVOUS) {
        ucs_trace("cxi tag rendezvous slot %d tag 0x%lx mlength %u "
                  "rlength %u get_issued %u remote_offset 0x%lx",
                  slot, (unsigned long)event->tgt_long.match_bits,
                  (unsigned)event->tgt_long.mlength,
                  (unsigned)event->tgt_long.rlength,
                  (unsigned)event->tgt_long.get_issued,
                  (unsigned long)event->tgt_long.remote_offset);
    } else {
        ucs_trace("cxi tag %s rndv slot %d tag 0x%lx mlength %u rlength %u",
                  (event->hdr.event_type == C_EVENT_PUT_OVERFLOW) ?
                          "ovf matched" :
                          "direct match",
                  slot, (unsigned long)event->tgt_long.match_bits,
                  (unsigned)event->tgt_long.mlength,
                  (unsigned)event->tgt_long.rlength);
        /*
         * match_bits is the real tag only on PUT/PUT_OVERFLOW; on
         * C_EVENT_RENDEZVOUS it is hardware bookkeeping, and event order is not
         * guaranteed.
         */
        priv->stag = event->tgt_long.match_bits;
    }
    priv->length      = event->tgt_long.rlength;
    priv->rndv_flags |= seen_bit;
    if (event->tgt_long.rlength > priv->posted_len) {
        /*
         * Truncation is against the posted buffer's capacity: mlength is 0 for
         * a rendezvous arrival.
         */
        priv->rndv_flags |= UCT_CXI_RNDV_FLAG_TRUNCATED;
    }

    if ((event->hdr.event_type == C_EVENT_RENDEZVOUS) &&
        ucs_unlikely(!event->tgt_long.get_issued)) {
        status = uct_cxi_iface_issue_rdzv_get(iface, event, (uint16_t)slot,
                                              priv->posted_len);
        if (ucs_unlikely(status != UCS_OK)) {
            /*
             * Resource exhaustion issuing the pull: fail now (no Reply will
             * arrive) and defer the slot reclaim, as the Put event may be
             * pending.
             */
            ucs_error("cxi tag failed to issue rdzv Get, slot %d", slot);
            uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot,
                                        UCT_CXI_RNDV_SEEN_REPLY, status);
            return;
        }
        /* SEEN_REPLY arrives later via uct_cxi_rdzv_get_comp() once this
         * Get's own C_EVENT_REPLY lands. */
    }
    /*
     * get_issued==1 (common): the NIC's own pull covers the whole message and
     * its REPLY marks SEEN_REPLY; the Put events need nothing (mlength is 0).
     */

    if ((priv->rndv_flags & UCT_CXI_RNDV_SEEN_REQUIRED) !=
        UCT_CXI_RNDV_SEEN_REQUIRED) {
        return;
    }

    uct_cxi_tag_slot_free(iface, slot);

    stag   = priv->stag;
    /* Cap the delivered length at the posted capacity on truncation, as the
     * eager path; otherwise priv->length never exceeds posted_len. */
    length = ucs_min(priv->length, priv->posted_len);
    /* A failed Get completes immediately via uct_cxi_iface_tag_rdzv_fail()
     * instead of reaching here, so only truncation is left to check. */
    status = (priv->rndv_flags & UCT_CXI_RNDV_FLAG_TRUNCATED) ?
                     UCS_ERR_MESSAGE_TRUNCATED :
                     UCS_OK;

    /* imm is always 0 for rendezvous per uct_ep_tag_rndv_zcopy's own doc.
     * inline_data is always NULL, same reason as the eager handler. */
    ctx->completed_cb(ctx, stag, 0, length, NULL, status);
}

/*
 * Completion of a rendezvous receive's pull Get (SEEN_REPLY): mark it and fire
 * completed_cb once UCT_CXI_RNDV_SEEN_REQUIRED is satisfied.
 */
static void uct_cxi_iface_tag_rdzv_reply_done(uct_cxi_iface_t *iface, int slot,
                                              uint8_t seen_bit,
                                              ucs_status_t get_status)
{
    uct_tag_context_t *ctx;
    uct_cxi_tag_ctx_priv_t *priv;
    uint64_t stag;
    uint32_t length;
    ucs_status_t status;

    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        /* Stale event for a resolved slot (e.g. a force-cancel): drop it. */
        ucs_trace("cxi tag rdzv reply stale slot %d already resolved, "
                  "dropping",
                  slot);
        return;
    }

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        uct_cxi_iface_tag_rdzv_cancel_seen(iface, slot, seen_bit);
        return;
    }

    ctx  = iface->tag.ctx[slot];
    priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;
    ucs_assertv(priv->slot == (uint16_t)slot, "priv->slot=%u slot=%d",
                priv->slot, slot);
    ucs_assertv(priv->rndv_flags & UCT_CXI_RNDV_FLAG_IS_RNDV,
                "slot=%d rndv_flags=0x%x", slot, priv->rndv_flags);

    if (ucs_unlikely(get_status != UCS_OK)) {
        /*
         * Fail now rather than accumulate: a failed pull has no partial
         * success.
         */
        uct_cxi_iface_tag_rdzv_fail(iface, ctx, slot, seen_bit, get_status);
        return;
    }

    priv->rndv_flags |= seen_bit;
    if ((priv->rndv_flags & UCT_CXI_RNDV_SEEN_REQUIRED) !=
        UCT_CXI_RNDV_SEEN_REQUIRED) {
        return;
    }

    stag   = priv->stag;
    length = ucs_min(priv->length, priv->posted_len);
    status = (priv->rndv_flags & UCT_CXI_RNDV_FLAG_TRUNCATED) ?
                     UCS_ERR_MESSAGE_TRUNCATED :
                     UCS_OK;

    uct_cxi_tag_slot_free(iface, slot);

    ctx->completed_cb(ctx, stag, 0, length, NULL, status);
}

/*
 * C_EVENT_REPLY of a NIC auto-issued (get_issued==1) rendezvous Get. Its
 * user_ptr is a bit-packed struct cxi_rdzv_user_ptr whose buffer_id is the
 * priority-LE slot. Called before the generic REPLY handling, which would cast
 * it to a send op.
 */
void uct_cxi_iface_tag_handle_rdzv_reply(uct_cxi_iface_t *iface,
                                         const union c_event *event)
{
    struct cxi_rdzv_user_ptr *user_ptr =
            (struct cxi_rdzv_user_ptr*)&event->init_short.user_ptr;
    ucs_status_t status = uct_cxi_rc_to_status(cxi_event_rc(event));

    ucs_trace("cxi tag rdzv get nic slot %u rc %d", user_ptr->buffer_id,
              cxi_event_rc(event));
    uct_cxi_iface_tag_rdzv_reply_done(iface, (int)user_ptr->buffer_id,
                                      UCT_CXI_RNDV_SEEN_REPLY, status);
}

/* uct_cxi_send_op_t::handler for a software-issued rendezvous Get's REPLY,
 * dispatched through the generic path (we built its user_ptr). */
void uct_cxi_rdzv_get_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_rdzv_get_op_t *rop = (uct_cxi_rdzv_get_op_t*)op;
    uct_cxi_iface_t *iface     = rop->iface;
    int slot                   = rop->slot;

    ucs_mpool_put(rop);
    uct_cxi_iface_tag_rdzv_reply_done(iface, slot, UCT_CXI_RNDV_SEEN_REPLY,
                                      status);
}

/*
 * C_EVENT_UNLINK on the tag PTE. The priority-LE APPEND sets
 * event_unlink_disable, so the automatic use_once unlink raises none. What
 * reaches here:
 *   - a cancel UNLINK that lost to a match (ENTRY_NOT_FOUND): drop;
 *   - a manual unlink of an overflow buffer at teardown: nothing to repost;
 *   - a genuine cancel confirmation (PRIORITY, C_RC_OK).
 * A winning UNLINK is a terminal disposition, so a force-cancelled slot is
 * reclaimed at once with no rndv_seen accumulation. Checks
 * cancel_ctx[slot].force before touching ctx/priv.
 */
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                     const union c_event *event)
{
    int slot;
    uct_tag_context_t *ctx;

    ucs_trace("cxi tag unlink buf_id %d ptl_list %d rc %d",
              (int)event->tgt_long.buffer_id, (int)event->tgt_long.ptl_list,
              cxi_event_rc(event));

    if (cxi_event_rc(event) == C_RC_ENTRY_NOT_FOUND) {
        ucs_trace("cxi tag unlink raced buf_id %d: lost to a winning "
                  "match, dropping",
                  (int)event->tgt_long.buffer_id);
        return;
    }

    if (event->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) {
        ucs_trace("cxi tag overflow LE C_EVENT_UNLINK buf %d (manual)",
                  (int)event->tgt_long.buffer_id);
        return;
    }

    slot = (int)event->tgt_long.buffer_id;
    if ((slot < 0) || (slot >= (int)iface->tag.max_outstanding) ||
        (iface->tag.ctx[slot] == NULL)) {
        return;
    }

    if (ucs_unlikely(iface->tag.cancel_ctx[slot].force)) {
        uct_cxi_tag_slot_free(iface, slot);
        iface->tag.cancel_ctx[slot].force = 0;
        return;
    }

    ctx = iface->tag.ctx[slot];
    ucs_assertv(((uct_cxi_tag_ctx_priv_t*)ctx->priv)->slot == (uint16_t)slot,
                "priv->slot=%u slot=%d",
                ((uct_cxi_tag_ctx_priv_t*)ctx->priv)->slot, slot);

    uct_cxi_tag_slot_free(iface, slot);

    ctx->completed_cb(ctx, 0, 0, 0, NULL, UCS_ERR_CANCELED);
}


/* Sender-side ops, analogues of cxi_am.c's short/bcopy/zcopy. */

/* The fields of a DMA Put to the tag PTE shared by all the tag sends. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_tag_dma_init(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, unsigned opcode,
                     uint8_t lac, uct_tag_t tag, void *user_ptr,
                     struct c_full_dma_cmd *cmd)
{
    cmd->command.opcode     = opcode;
    cmd->index_ext          = ep->dfa_tag_idx_ext;
    cmd->lac                = lac;
    cmd->event_send_disable = 1;
    cmd->initiator          = iface->match_id;
    cmd->eq                 = iface->tx_eq.evtq->eqn;
    cmd->dfa                = ep->dfa_tag;
    cmd->match_bits         = tag;
    cmd->user_ptr           = (uint64_t)(uintptr_t)user_ptr;
}

/*
 * The unrestricted IDC tag send (up to 192 B) of an eager message with only \a
 * imm out of band, and of a software rendezvous request (imm
 * UCT_CXI_TAG_SW_RNDV_IMM), charged as eager tag traffic.
 */
static ucs_status_t uct_cxi_tag_short_send(uct_cxi_ep_t *ep, uct_tag_t tag,
                                           uint64_t imm, const void *data,
                                           size_t length, const char *what)
{
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    unsigned units         = UCT_CXI_FC_UNITS(length);
    ucs_status_t status;
    int credited;

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

    ucs_trace("cxi tag send short ep %p tag 0x%lx len %zu imm 0x%lx", ep,
              (unsigned long)tag, length, (unsigned long)imm);
    return UCS_OK;
}

/*
 * Unrestricted IDC tag send (up to 192 B), with no header reservation unlike
 * AM: imm travels in header_data, and eager_short has no imm (0).
 */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
    return uct_cxi_tag_short_send(ucs_derived_of(tl_ep, uct_cxi_ep_t), tag, 0,
                                  data, length, "tag_eager_short");
}

/* Unrestricted DMA tag send via a bounce buffer from the shared desc_pool. */
ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag, uint64_t imm,
                                   uct_pack_callback_t pack_cb, void *arg,
                                   unsigned flags)
{
    uct_cxi_ep_t *ep          = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface    = uct_cxi_ep_iface(ep);
    struct c_full_dma_cmd cmd = {};
    uct_cxi_send_desc_t *desc;
    size_t length;
    unsigned units;
    ucs_status_t status;
    int credited;

    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        /* The mark of a software rendezvous request. */
        return UCS_ERR_INVALID_PARAM;
    }

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return (ssize_t)UCS_ERR_NO_RESOURCE;
    }

    /*
     * As for an AM: the length is known only once packed, so ask for one unit
     * now and charge the real cost afterwards.
     */
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
    units = UCT_CXI_FC_UNITS(length);

    uct_cxi_send_op_set(&desc->op, ep, NULL, uct_cxi_send_desc_put_comp);

    uct_cxi_tag_dma_init(ep, iface, C_CMD_PUT, desc->lac, tag, desc, &cmd);
    cmd.header_data = imm;
    cmd.local_addr  = desc->iova;
    cmd.request_len = (uint32_t)length;

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "tag_eager_bcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(desc);
        return (ssize_t)status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);
    uct_cxi_op_fc_set(&desc->op, credited, UCT_CXI_FC_TAG,
                      UCT_CXI_FC_SLOTS_TAG_EAGER, units);
    ucs_trace("cxi tag send bcopy ep %p tag 0x%lx imm 0x%lx len %zu", ep,
              (unsigned long)tag, (unsigned long)imm, length);
    return (ssize_t)length;
}

/* Unrestricted DMA tag send from the caller's registered buffer. */
ucs_status_t uct_cxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp)
{
    uct_cxi_ep_t *ep           = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface     = uct_cxi_ep_iface(ep);
    uct_cxi_mem_handle_t *memh = (uct_cxi_mem_handle_t*)iov[0].memh;
    size_t length              = uct_iov_get_length(iov);
    unsigned units             = UCT_CXI_FC_UNITS(length);
    struct c_full_dma_cmd cmd  = {};
    uct_cxi_send_op_t *op;
    ucs_status_t status;
    int credited;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_eager_zcopy");

    if (ucs_unlikely(imm == UCT_CXI_TAG_SW_RNDV_IMM)) {
        /* The mark of a software rendezvous request. */
        return UCS_ERR_INVALID_PARAM;
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
    uct_cxi_send_op_set(op, ep, comp, NULL);

    uct_cxi_tag_dma_init(ep, iface, C_CMD_PUT, memh->cxi_md->lac, tag, op,
                         &cmd);
    cmd.header_data = imm;
    cmd.local_addr  = uct_cxi_mem_iova(memh, iov[0].buffer);
    cmd.request_len = (uint32_t)length;

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "tag_eager_zcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(op);
        return status;
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                     units);
    uct_cxi_op_fc_set(op, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_EAGER,
                      units);
    ucs_trace("cxi tag send zcopy ep %p tag 0x%lx imm 0x%lx len %zu", ep,
              (unsigned long)tag, (unsigned long)imm, length);
    return UCS_INPROGRESS;
}


/* Rendezvous ops. */

/*
 * Handler for a rendezvous Put's own local C_EVENT_ACK (C_CMD_RENDEZVOUS_PUT
 * raises it despite event_send_disable, as libfabric expects). On success this
 * is not the completion of the rndv comp: that fires when the peer's Get lands,
 * so the op stays in iface->rdzv.ops[]. On failure the Put never landed, so
 * free its id and fire comp with the error.
 */
void uct_cxi_rdzv_put_ack_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_rdzv_op_t *rop = (uct_cxi_rdzv_op_t*)op;
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(rop->op.ep);

    if (ucs_likely(status == UCS_OK)) {
        return;
    }

    ucs_error("cxi tag rndv put ack failed: %s", ucs_status_string(status));
    rop->valid                                     = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = rop->id;
    if (rop->comp != NULL) {
        uct_invoke_completion(rop->comp, status);
    }
}

/*
 * Expose \a iov for a native hardware pull on ep->dfa_tag (C_CMD_RENDEZVOUS_PUT
 * is a distinct opcode on the same matching PTE). remote_offset is the iov's
 * address and cmd.rendezvous_id this op's index in iface->rdzv.ops[]
 * (uct_cxi_rdzv_op_t). UCP passes the 17-byte offload rendezvous header on
 * every call: only req_id varies and goes in header_data (eager_length is
 * always 0); ep_id and md_index travel once, in the announce on the ep's first
 * call (receive side: iface->tag.rndv_peer_cache). Returns
 * &iface->rdzv.ops[id], tracked until the peer's Get lands or
 * uct_ep_tag_rndv_cancel().
 */
ucs_status_ptr_t
uct_cxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag, const void *header,
                          unsigned header_length, const uct_iov_t *iov,
                          size_t iovcnt, unsigned flags, uct_completion_t *comp)
{
    uct_cxi_ep_t *ep                     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface               = uct_cxi_ep_iface(ep);
    uct_cxi_mem_handle_t *memh           = (uct_cxi_mem_handle_t*)iov[0].memh;
    size_t length                        = uct_iov_get_length(iov);
    const uct_cxi_rndv_hdr_wire_t *hdr_w = header;
    struct c_full_dma_cmd cmd            = {};
    uct_cxi_rdzv_op_t *rop;
    uint64_t local_addr;
    uint64_t header_data;
    ucs_status_t status;
    uint32_t id;
    int credited;

    if (ucs_unlikely(iovcnt != 1ul)) {
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    if (uct_cxi_iface_tx_blocked(iface, &iface->tag.fc)) {
        return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);
    }

    /*
     * Only req_id varies per send; header_length is always
     * sizeof(uct_cxi_rndv_hdr_wire_t) with this protocol, guard anyway.
     */
    ucs_assert(header_length >= sizeof(*hdr_w));
    header_data = hdr_w->req_id;

    if (ucs_unlikely(!ep->rndv_hdr_announced)) {
        status = uct_cxi_ep_send_rndv_hdr_announce(ep, hdr_w->ep_id,
                                                   hdr_w->md_index);
        if (ucs_unlikely(status != UCS_OK)) {
            /* No id consumed yet: UCP retries this send. */
            return UCS_STATUS_PTR(status);
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

    local_addr = uct_cxi_mem_iova(memh, iov[0].buffer);

    /*
     * Where a target that takes this off its unexpected list finds the source
     * address. A plain store suffices: the doorbell is rung after it.
     */
    iface->rdzv.addr_table[id] = local_addr;

    /* The op has an ep, so the generic ACK accounting applies; the completion
     * is rop->comp, fired once the peer's Get lands. */
    uct_cxi_send_op_set(&rop->op, ep, NULL, uct_cxi_rdzv_put_ack_comp);
    rop->comp   = comp;
    rop->length = (uint32_t)length;
    rop->id     = (uint8_t)id;
    rop->valid  = 1;

    uct_cxi_tag_dma_init(ep, iface, C_CMD_RENDEZVOUS_PUT, memh->cxi_md->lac,
                         tag, &rop->op, &cmd);
    cmd.local_addr         = local_addr;
    cmd.request_len        = (uint32_t)length;
    cmd.remote_offset      = local_addr;
    cmd.header_data        = header_data;
    cmd.use_offset_for_get = 1;
    cmd.rendezvous_id      = (uint8_t)id;

    status = uct_cxi_ep_dma_post(ep, iface, &cmd, "tag_rndv_zcopy");
    if (ucs_unlikely(status != UCS_OK)) {
        rop->valid                                     = 0;
        iface->rdzv.free_ids[iface->rdzv.free_count++] = id;
        return UCS_STATUS_PTR(status);
    }

    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, UCT_CXI_FC_SLOTS_TAG_RNDV,
                     0);
    uct_cxi_op_fc_set(&rop->op, credited, UCT_CXI_FC_TAG,
                      UCT_CXI_FC_SLOTS_TAG_RNDV, 0);
    ucs_trace("cxi tag rndv send ep %p tag 0x%lx id %u local_addr 0x%lx "
              "len %zu",
              ep, (unsigned long)tag, id, (unsigned long)local_addr, length);
    return rop;
}

/*
 * Software-only removal: the op is removed only here or by tag_handle_rdzv_get,
 * and UCP never cancels a completed op.
 */
ucs_status_t uct_cxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *op)
{
    uct_cxi_ep_t *ep       = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface = uct_cxi_ep_iface(ep);
    uct_cxi_rdzv_op_t *rop = (uct_cxi_rdzv_op_t*)op;

    rop->valid                                     = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = rop->id;
    return UCS_OK;
}

/*
 * C_EVENT_GET on iface->rdzv.pte: a peer's Get read our exposed LE. match_bits
 * carries the op's id for an O(1) lookup in iface->rdzv.ops[]; only its low 8
 * bits are ours (bounding UCT_CXI_RDZV_MAX_OUTSTANDING_MAX at 256). Fires comp,
 * the buffer being reusable, unless the receiver's UCP issued the Get
 * (UCT_CXI_RDZV_MATCH_SW_PULL): its ATS ends that rendezvous by cancelling the
 * op.
 */
void uct_cxi_iface_tag_handle_rdzv_get(uct_cxi_iface_t *iface,
                                       const union c_event *event)
{
    uint64_t match_bits = event->tgt_long.match_bits;
    uint32_t id         = (uint32_t)(match_bits & 0xFF);
    uct_cxi_rdzv_op_t *rop;
    ucs_status_t status;

    if (match_bits & UCT_CXI_RDZV_MATCH_SW_PULL) {
        ucs_trace("cxi tag rndv pulled id %u", id);
        return;
    }

    if ((id >= iface->rdzv.max_outstanding) || !iface->rdzv.ops[id].valid) {
        ucs_trace("cxi tag rndv got stale id %u: no matching outstanding "
                  "rndv_zcopy, already cancelled?",
                  id);
        return;
    }

    rop                                            = &iface->rdzv.ops[id];
    rop->valid                                     = 0;
    iface->rdzv.free_ids[iface->rdzv.free_count++] = id;
    status = uct_cxi_rc_to_status(cxi_event_rc(event));
    ucs_trace("cxi tag rndv got id %u len %u rc %d", id, rop->length,
              cxi_event_rc(event));

    if (rop->comp != NULL) {
        uct_invoke_completion(rop->comp, status);
    }
}

/*
 * A software rendezvous request: UCP's RTS and the packed key of the sender's
 * buffer as the payload of a tagged message, so it is matched in order with
 * other tagged messages and handled by the receiver's UCP (the NIC moves no
 * data). It is an eager message but for its header_data
 * (UCT_CXI_TAG_SW_RNDV_IMM); the receiver hands it to rndv_cb with no remote
 * address. As on InfiniBand nothing completes it: UCS_OK when sent.
 */
ucs_status_t uct_cxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length, unsigned flags)
{
    return uct_cxi_tag_short_send(ucs_derived_of(tl_ep, uct_cxi_ep_t), tag,
                                  UCT_CXI_TAG_SW_RNDV_IMM, header,
                                  header_length, "tag_rndv_request");
}


/* Receiver-side ops (priority-LE posting, the hot path). */

/*
 * Would a receive for \a tag and \a mask match a message UCP has yet to be told
 * of, held in a stream? That message is off the NIC's list, so a receive posted
 * there would take a later message while UCP matches the held one to the oldest
 * receive: this one. The receive is refused, so UCP keeps it in software. A
 * tombstone does not count. One load of unexp_held when no rendezvous is held.
 */
static int
uct_cxi_tag_held_matches(uct_cxi_iface_t *iface, uct_tag_t tag, uct_tag_t mask)
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
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_mem_handle_t *memh;
    uct_cxi_tag_ctx_priv_t *priv;
    uint16_t slot;
    struct c_target_cmd le = iface->tag.recv_le;
    uct_cxi_tag_pend_t *e;
    int ret;

    UCT_CHECK_IOV_SIZE(iovcnt, 1ul, "tag_recv_zcopy");

    /*
     * Exactly fills UCT_TAG_PRIV_LEN with recv_addr added: catch growth here.
     */
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
        ucs_trace("cxi tag pri le refused tag 0x%lx tag_mask 0x%lx: matches "
                  "an unexpected message held for UCP",
                  (unsigned long)tag, (unsigned long)tag_mask);
        return UCS_ERR_NO_RESOURCE;
    }

    memh = (uct_cxi_mem_handle_t*)iov[0].memh;
    slot = iface->tag.free_list[--iface->tag.free_count];

    priv                 = (uct_cxi_tag_ctx_priv_t*)ctx->priv;
    priv->slot           = slot;
    priv->rndv_flags     = 0;
    priv->posted_len     = (uint32_t)iov[0].length;
    priv->recv_addr      = (uint64_t)(uintptr_t)iov[0].buffer;
    iface->tag.ctx[slot] = ctx;

    le.buffer_id   = slot;
    le.lac         = memh->cxi_md->lac;
    le.start       = uct_cxi_mem_iova(memh, iov[0].buffer);
    le.length      = iov[0].length;
    le.ignore_bits = ~tag_mask;
    le.match_bits  = tag;

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &le);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tag_slot_free(iface, slot);
        uct_cxi_tx_emit_error(NULL, "tag_recv_zcopy priority LE append", ret);
        return UCS_ERR_NO_RESOURCE;
    }
    cxi_cq_ring(iface->tgt.cmdq);

    /* It can take an unexpected message from now on. */
    iface->tag.slot_pos[slot] = iface->tag.pend_head;
    e       = &iface->tag.pend[iface->tag.pend_head++ & UCT_CXI_TAG_PEND_MASK];
    e->tag  = tag;
    e->mask = tag_mask;
    e->slot = slot;
    e->state = UCT_CXI_TAG_PEND_PENDING;
    if (++iface->tag.fence_posts >= iface->tag.fence_interval) {
        uct_cxi_tag_fence_post(iface);
    }

    ucs_trace("cxi tag pri le post slot %u tag 0x%lx tag_mask 0x%lx",
              (unsigned)slot, tag, tag_mask);
    return UCS_OK;
}

ucs_status_t uct_cxi_iface_tag_recv_cancel(uct_iface_h tl_iface,
                                           uct_tag_context_t *ctx, int force)
{
    uct_cxi_iface_t *iface       = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    uct_cxi_tag_ctx_priv_t *priv = (uct_cxi_tag_ctx_priv_t*)ctx->priv;
    struct c_target_cmd cmd      = {};
    uint32_t pos                 = iface->tag.slot_pos[priv->slot];

    /*
     * A message arriving from now on is not this receive's to take, whatever
     * becomes of the cancel.
     */
    if (uct_cxi_tag_pend_in_window(iface, pos) &&
        (iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK].state ==
         UCT_CXI_TAG_PEND_PENDING)) {
        iface->tag.pend[pos & UCT_CXI_TAG_PEND_MASK].state =
                UCT_CXI_TAG_PEND_SPENT;
    }

    if (force) {
        /*
         * priv is read here for the last time, while ctx is still valid (with
         * force=1 UCP may recycle it at once). Snapshot the rendezvous
         * accumulation into iface-owned memory; neither ctx nor priv may be
         * touched for this slot from here on.
         */
        iface->tag.cancel_ctx[priv->slot].rndv_seen = priv->rndv_flags;
        iface->tag.cancel_ctx[priv->slot].force     = 1;
    }

    cmd.command.opcode = C_CMD_TGT_UNLINK;
    cmd.ptl_list       = C_PTL_LIST_PRIORITY;
    cmd.ptlte_index    = iface->tag.ptn;
    cmd.buffer_id      = priv->slot;

    /*
     * The UNLINK must not be lost to a full command queue: with force=1 UCP
     * assumes the cancel done and will not retry.
     */
    return uct_cxi_iface_tgt_post(iface, &cmd);
}
