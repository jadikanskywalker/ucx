/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching offload declarations.
 *
 * Uses Cassini's real matching-list capability (is_matching=1, sender's tag
 * compared via match_bits/ignore_bits) -- unlike the AM PTE, which is also
 * is_matching=1 but always wildcards (match_bits=0/ignore_bits=UINT64_MAX).
 *
 * Two independent pieces on one PTE (pid_offset = UCT_CXI_PTE_TAG):
 *   - Priority-list LEs, one per uct_iface_tag_recv_zcopy() call, use_once,
 *     bound to the caller's own registered destination buffer for direct
 *     hardware DMA (zero software copy on a direct match).
 *   - A true Portals4 overflow-list ring (C_PTL_LIST_OVERFLOW,
 *     unexpected_hdr_disable=0) catching messages with no matching
 *     priority LE posted yet -- structurally modeled on the AM PTE's
 *     buffer ring (contiguous alloc, buffer_id-indexed, manage_local), but
 *     genuinely new semantics: unexpected data is copied out immediately
 *     and handed to UCP's own SW tag-matching via eager_cb/rndv_cb, never
 *     retained waiting for a future post.
 */

#ifndef UCT_CXI_TAG_H
#define UCT_CXI_TAG_H

#include "cxi_ep.h"
#include <uct/api/uct.h>

/* min_free threshold for the overflow ring: a small fixed margin, matching
 * UCT_CXI_AM_MIN_FREE's already-proven pattern (see cxi_iface.h) rather
 * than scaling to the max eager size -- Cassini's manage_local placement
 * logic evidently handles an oversized-relative-to-remaining-space Put on
 * its own; a large fixed threshold is unvalidated and unnecessary here. */
#define UCT_CXI_TAG_OVF_MIN_FREE      256u

/* Hard ceiling on TAG_MAX_OUTSTANDING: buffer_id (the slot-correlation
 * field) is uint16_t. */
#define UCT_CXI_TAG_MAX_OUTSTANDING_MAX  65535u

/* Sentinel buffer_id for our own SEARCH_AND_DELETE command, always one
 * past the maximum possible valid priority-LE slot -- lets
 * tag_handle_match() tell its own delete-confirmation event apart from a
 * genuine delayed match. Currently unused: SEARCH_AND_DELETE emission is
 * disabled (see the #else branch of tag_handle_ovf_arrival() in
 * cxi_tag.c) pending a decision on unexpected-message handling. Kept for
 * when that code path is re-enabled. */
#define UCT_CXI_TAG_SEARCH_DELETE_SENTINEL  0xFFFFu

/*
 * Private per-request state stored in uct_tag_context_t::priv
 * (UCT_TAG_PRIV_LEN = 32 bytes available).
 */
typedef struct uct_cxi_tag_ctx_priv {
    uint16_t slot;            /* Index into iface->tag.ctx[]/free_list[] */
    uint8_t  cancel_force;    /* Set by tag_recv_cancel(force=1). The
                             * priority-LE APPEND sets event_unlink_
                             * disable=1 (matches libfabric's own
                             * _cxip_recv_req()), so the automatic
                             * use_once-on-match unlink never generates an
                             * event -- tag_handle_match() owns that case
                             * entirely on its own. Every C_EVENT_UNLINK
                             * that reaches uct_cxi_iface_tag_handle_unlink()
                             * is therefore unambiguously a real explicit
                             * cancel confirmation; this flag only controls
                             * whether completed_cb is invoked for it. */
} uct_cxi_tag_ctx_priv_t;


/* PTE lifecycle -- called from cxi_iface.c's UCS_CLASS_INIT/CLEANUP_FUNC.
 * open_tag_pte is a no-op (returns UCS_OK, iface->tag.pte stays NULL) if
 * UCP didn't supply both HW_TM callbacks or UCX_CXI_TAG_ENABLE=no -- UCP
 * transparently falls back to SW tag matching over AM in that case. */
ucs_status_t uct_cxi_iface_open_tag_pte(uct_cxi_iface_t *self,
                                         struct cxil_lni *lni,
                                         const uct_cxi_iface_config_t *config,
                                         const uct_iface_params_t *params);
void uct_cxi_iface_close_tag_pte(uct_cxi_iface_t *self);

/*
 * Event dispatch, called from cxi_iface.c's iface_progress() once it has
 * identified event->tgt_long.ptlte_index == iface->tag.pte->ptn.
 *
 * C_EVENT_PUT fires for BOTH LE populations on this one PTE and must be
 * further split by event->tgt_long.ptl_list (the caller's job, since it
 * already branches on ptlte_index):
 *   - C_PTL_LIST_OVERFLOW -> tag_handle_ovf_arrival (unexpected message
 *     landed with no priority LE posted for it yet).
 *   - C_PTL_LIST_PRIORITY -> tag_handle_match (direct match: a priority LE
 *     was already posted, data landed straight into the caller's buffer).
 * tag_handle_match is also the handler for C_EVENT_PUT_OVERFLOW (the
 * delayed-correlation case: the message had already landed in the overflow
 * ring before this priority LE was posted) -- same disposition either way.
 */
void uct_cxi_iface_tag_handle_ovf_arrival(uct_cxi_iface_t *iface,
                                          const union c_event *event);
void uct_cxi_iface_tag_handle_match(uct_cxi_iface_t *iface,
                                    const union c_event *event);
void uct_cxi_iface_tag_handle_unlink(uct_cxi_iface_t *iface,
                                      const union c_event *event);

/* UCT tag-matching ops -- installed into uct_cxi_iface_ops in cxi_iface.c.
 * Phase A only: eager_short/bcopy/zcopy and tag_recv_zcopy/cancel.
 * ep_tag_rndv_zcopy/cancel/request stay ucs_empty_function_return_unsupported
 * -- UCP already falls back to SW rendezvous over AM when
 * UCT_IFACE_FLAG_TAG_RNDV_ZCOPY is unset, so no stub is needed here. */
ucs_status_t uct_cxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length);

ssize_t uct_cxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                    uint64_t imm, uct_pack_callback_t pack_cb,
                                    void *arg, unsigned flags);

ucs_status_t uct_cxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp);

ucs_status_t uct_cxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx);

ucs_status_t uct_cxi_iface_tag_recv_cancel(uct_iface_h tl_iface,
                                           uct_tag_context_t *ctx, int force);

#endif /* UCT_CXI_TAG_H */
