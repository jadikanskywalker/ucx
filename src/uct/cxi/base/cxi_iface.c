/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT interface: opens the per-iface libcxi resources (event queues,
 * command queues, domain, PTEs and buffers), runs the progress loop and
 * dispatches its events. Resources are allocated in UCS_CLASS_INIT_FUNC order
 * and destroyed in reverse. The RMA PTEs, one per LAC, are all opened up front
 * so that ep->dfa_rma[] needs no "is it open" check.
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
                                  "reliably triggers UCS_ERR_NO_RESOURCE / pending-retry.\n"
                                  "Total sends in flight are separately capped by the TX\n"
                                  "event queue depth (TX_EQ_SIZE). -1 means 512.\n"
                                  "Workloads with many concurrently-busy endpoints on one\n"
                                  "interface should raise this together with\n"
                                  "TX_OP_MAX_BUFS — per-endpoint size for expected\n"
                                  "in-flight operation count."),

    UCT_IFACE_MPOOL_CONFIG_FIELDS("TX_OP_", 512, 256, 16mb, 2.0,
                                  "send-op tracking",
                                  ucs_offsetof(uct_cxi_iface_config_t, op_mp),
                                  "\nUsed by put/get/AM short and zcopy, and AMO post/fetch,\n"
                                  "for completion tracking (no DMA-registered memory).\n"
                                  "MAX_BUFS default (512) is bounded for the same reason as\n"
                                  "BCOPY_MAX_BUFS above; -1 means 512.\n"
                                  "Raise together with BCOPY_MAX_BUFS for workloads\n"
                                  "with many concurrently-busy endpoints."),

    {"EQ_SIZE", "-1",
     "RX event queue depth (number of hardware events): everything the NIC\n"
     "reports for this iface's own portal table entries, i.e. incoming\n"
     "traffic and PTE state changes. -1 (default) sizes it for\n"
     "FC_ACTIVE_SENDERS peers each using their full FC_MSG_WINDOW, with flow\n"
     "control on or off (a warning is logged if an explicit value is\n"
     "smaller). Rounded up to a whole number of pages (64 events).\n"
     "Initiator-side completions use a separate queue, see TX_EQ_SIZE.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_size),
     UCS_CONFIG_TYPE_INT},

    {"TX_EQ_SIZE", "-1",
     "TX event queue depth: completions (ACK/REPLY) of commands this iface\n"
     "issued. -1 (default) resolves to 1024. A send holds one slot from the\n"
     "moment it is issued until its completion is processed, so this also\n"
     "caps the number of sends in flight (minus a few slots reserved for\n"
     "get_short and error events): beyond it sends return\n"
     "UCS_ERR_NO_RESOURCE and wait on the pending queue. Raise it for\n"
     "workloads that need more concurrent sends than that; TX_OP_MAX_BUFS\n"
     "and BCOPY_MAX_BUFS separately bound the pool-backed ones.",
     ucs_offsetof(uct_cxi_iface_config_t, tx_eq_size),
     UCS_CONFIG_TYPE_INT},

    {"EQ_MAX_POLL", "16",
     "Max events drained from each EQ (RX and TX) per iface_progress() call, matching\n"
     "the bounded-poll-per-call pattern every other UCX transport uses\n"
     "(e.g. RC/UD/DC's TX/RX_MAX_POLL, TCP's UCT_TCP_MAX_EVENTS) instead of\n"
     "draining to empty. Without this bound, a steady incoming flood could\n"
     "keep the loop running past the point where the post-loop\n"
     "EQ_DYNAMIC_GROWTH fill-threshold and EQ_DRAIN_PCT drop checks would\n"
     "still have time to act before the EQ actually fills.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_max_poll),
     UCS_CONFIG_TYPE_UINT},

    {"EQ_RESERVED_SLOTS", "64",
     "Number of RX EQ slots reserved so incoming messages cannot crowd out\n"
     "the events that are not themselves incoming traffic: PTE state\n"
     "changes and the results of this iface's own target commands. One-\n"
     "sided: those events may use the full EQ, this only blocks incoming-\n"
     "message events from the reserved portion. Incoming messages are what\n"
     "flow control (FC_*) accounts for, so this only has to cover the\n"
     "others; PTE flow control is what actually prevents data loss\n"
     "regardless of this setting.",
     ucs_offsetof(uct_cxi_iface_config_t, eq_reserved_slots),
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
     "Preemptively grow (double) the RX EQ when its fill level crosses\n"
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

    {"AM_RX_NUM_BUFS", "auto",
     "Number of AM receive buffers rotated on the PRIORITY list. Auto sizes\n"
     "the ring for FC_ACTIVE_SENDERS peers each using their full\n"
     "FC_BYTE_WINDOW, with flow control on or off (a warning is logged if an\n"
     "explicit value is smaller). Hard ceiling UCT_CXI_AM_RX_NUM_BUFS_MAX\n"
     "(cxi_iface.h).",
     ucs_offsetof(uct_cxi_iface_config_t, am_rx_num_bufs),
     UCS_CONFIG_TYPE_ULUNITS},

    {"AM_RX_BUF_SIZE", "auto",
     "Size of each AM receive buffer in bytes. Auto is the greater of 1 MiB\n"
     "and four times the largest message. Raised to twice the largest message\n"
     "if smaller:\n"
     "the NIC retires a buffer once less than a maximum-size message is left\n"
     "in it, so a smaller one would be retired after every message.",
     ucs_offsetof(uct_cxi_iface_config_t, am_rx_buf_size),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"AM_MAX_ZCOPY", "8k",
     "Largest AM zcopy header + payload in bytes, as advertised to the\n"
     "upper layer. Together with MAX_BCOPY it sets the largest message the\n"
     "AM receive buffers must take. The default matches the IB RC segment\n"
     "size; larger messages use rendezvous. At most 16 MiB - 1.",
     ucs_offsetof(uct_cxi_iface_config_t, am_max_zcopy),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"TAG_ENABLE", "try",
     "Enable hardware tag-matching offload when UCP requests it. \"no\"\n"
     "force-disables it even if requested, falling back to UCX's existing\n"
     "software tag matching over AM.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_enable),
     UCS_CONFIG_TYPE_TERNARY},

    {"TAG_OVERFLOW_NUM_BUFS", "auto",
     "Number of overflow-list buffers rotated for unexpected tagged\n"
     "messages (no priority LE posted for them yet). Auto sizes the ring for\n"
     "FC_ACTIVE_SENDERS peers each using their full FC_TAG_BYTE_WINDOW, with\n"
     "flow control on or off (a warning is logged if an explicit value is\n"
     "smaller). Hard ceiling UCT_CXI_TAG_OVF_NUM_BUFS_MAX (cxi_tag.h).",
     ucs_offsetof(uct_cxi_iface_config_t, tag_ovf_num_bufs),
     UCS_CONFIG_TYPE_ULUNITS},

    {"TAG_OVERFLOW_BUF_SIZE", "auto",
     "Size of each overflow-list buffer in bytes. Auto is the greater of\n"
     "1 MiB and four times TAG_EAGER_MAX. Raised to twice TAG_EAGER_MAX if\n"
     "smaller: the\n"
     "NIC retires a buffer once less than a maximum-size message is left in\n"
     "it, so a smaller one would be retired after every message.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_ovf_buf_size),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"TAG_EAGER_MAX", "256k",
     "Maximum eager tag message in bytes, as advertised (bcopy is also\n"
     "limited by MAX_BCOPY). Larger messages use rendezvous. The default is\n"
     "the most UCP sends eagerly unless told to (UCX_RNDV_SEND_NBR_THRESH).\n"
     "Also the overflow buffers' min_free, so that any message fits in what\n"
     "is left of a linked buffer, and half their minimum size. Peers must\n"
     "use the same value.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_eager_max),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"TAG_MAX_OUTSTANDING", "512",
     "Maximum number of simultaneously-posted priority-list receive LEs.\n"
     "Hard ceiling UCT_CXI_TAG_MAX_OUTSTANDING_MAX (the hardware buffer_id\n"
     "correlation field is 16 bits, and the two ids above the receives' are\n"
     "reserved for SEARCH_AND_DELETE and fences, see cxi_tag.h).",
     ucs_offsetof(uct_cxi_iface_config_t, tag_max_outstanding),
     UCS_CONFIG_TYPE_UINT},

    {"TAG_FENCE_INTERVAL", "32",
     "Number of posted tag receives between fences. A fence is a search that\n"
     "matches nothing, whose event tells that every receive before it has\n"
     "been appended, so that the unexpected messages they can still take\n"
     "have been told of: the receives not covered by one are what an\n"
     "unexpected message is matched against (at most 512, then receives are\n"
     "refused and matched in software). A smaller interval keeps that list\n"
     "short, at the cost of an event per fence.",
     ucs_offsetof(uct_cxi_iface_config_t, tag_fence_interval),
     UCS_CONFIG_TYPE_UINT},

    {"FC_MSG_WINDOW", "512",
     "Receive event queue slots granted to each peer: how many events one\n"
     "peer may have outstanding in this interface's queue at a time. Shared\n"
     "by Active Messages and tag matching. An Active Message takes one slot;\n"
     "so does an eager tag message that matches no posted receive, and a\n"
     "rendezvous one takes two (the receive's own events are accounted\n"
     "separately). Must be at least 2. Without flow control it is the load\n"
     "the receive queue is sized for, no credits being granted.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_msg_window),
     UCS_CONFIG_TYPE_UINT},

    {"FC_BYTE_WINDOW", "1m",
     "Active Message buffer credits granted to each peer: how many bytes\n"
     "one peer may have outstanding in this interface's AM receive buffers\n"
     "at a time (counted in 64-byte units). Must be at least the largest\n"
     "Active Message a peer may send. Without flow control it is the load\n"
     "the AM receive ring is sized for.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_byte_window),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"FC_TAG_BYTE_WINDOW", "512k",
     "Tag matching buffer credits granted to each peer: how many bytes one\n"
     "peer may have outstanding in this interface's tag overflow buffers at\n"
     "a time (counted in 64-byte units). Must be at least TAG_EAGER_MAX. The\n"
     "default is two maximum-size messages: a message that matches a posted\n"
     "receive is charged only until its ACK, so this is ample for bandwidth,\n"
     "and it keeps the overflow ring no larger than the AM ring. Without flow\n"
     "control it is the load the overflow ring is sized for.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_tag_byte_window),
     UCS_CONFIG_TYPE_MEMUNITS},

    {"FC_ACTIVE_SENDERS", "8",
     "Number of peers that may each send up to their full FC_MSG_WINDOW,\n"
     "FC_BYTE_WINDOW and FC_TAG_BYTE_WINDOW at the same time. Sizes the AM\n"
     "receive ring, the tag overflow ring, the table of unexpected tag\n"
     "messages and the RX EQ (unless AM_RX_NUM_BUFS, AM_RX_BUF_SIZE,\n"
     "TAG_OVERFLOW_NUM_BUFS, TAG_OVERFLOW_BUF_SIZE or EQ_SIZE are set), so\n"
     "pinned memory grows with it. The sizing is the same with flow control\n"
     "on and off (without it, nothing paces the senders to this load: see\n"
     "FC_ENABLE). Credits pace senders but do not stop more peers than this\n"
     "from overrunning the ring; the PTE flow control and recovery path is\n"
     "the backstop for that.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_active_senders),
     UCS_CONFIG_TYPE_UINT},

#ifndef UCT_CXI_DISABLE_FC
    {"CTRL_EQ_SIZE", "-1",
     "Control event queue depth (number of hardware events): the control\n"
     "messages that arrive (handshakes, credit grants) and the completions\n"
     "of those sent, which have slots of their own reserved (64). -1\n"
     "(default) resolves to 256. A message that arrives when no slot is\n"
     "free is refused and sent again by its sender. Rounded up to a whole\n"
     "number of pages (64 events).",
     ucs_offsetof(uct_cxi_iface_config_t, ctrl_eq_size),
     UCS_CONFIG_TYPE_INT},

    {"FC_ENABLE", "y",
     "Connected-endpoint flow control: open the control PTE and handshake\n"
     "with each peer when an endpoint to it is created. When off, this\n"
     "interface neither opens the control PTE nor handshakes, and peers\n"
     "treat it as a plain connectionless peer. Without flow control nothing\n"
     "limits what a sender puts in the receiver's queues: a target that falls\n"
     "behind (for example under a stream of small tagged messages) has its\n"
     "portal table entry disabled by the hardware, and the messages sent\n"
     "meanwhile are lost. For bring-up and debugging only; the same holds\n"
     "for a build configured with --disable-cxi-fc.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_enable),
     UCS_CONFIG_TYPE_BOOL},

    {"FC_CONNECT_TIMEOUT", "30s",
     "Give up on a peer's handshake after this long without a reply.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_connect_timeout),
     UCS_CONFIG_TYPE_TIME},

    {"FC_GRANT_THRESH", "0.5",
     "Hand credits back to a peer on a message of their own once this\n"
     "fraction of its window (messages, or bytes) has been processed and not\n"
     "yet returned. Credits also ride for free on any Active Message sent to\n"
     "that peer, so this only matters when there is none: lower values return\n"
     "credits sooner at the cost of more control messages.",
     ucs_offsetof(uct_cxi_iface_config_t, fc_grant_thresh),
     UCS_CONFIG_TYPE_DOUBLE},
#endif

    {NULL}
};

static UCS_CLASS_DEFINE_DELETE_FUNC(uct_cxi_iface_t, uct_iface_t);

/* Allocate, map and enable the RMA PTE of \a lac and post its catch-all LE. */
static ucs_status_t
uct_cxi_iface_open_rma_pte(uct_cxi_iface_t *self, struct cxil_lni *lni,
                            uint8_t lac)
{
    ucs_status_t              status;
    int                       ret;

    {
        /* No en_flowctrl: the LE raises no event on success, so an operation
         * needs no EQ slot and a full queue cannot turn it away. A failed one
         * raises an event, which a full queue drops (progress reports it). */
        struct cxi_pt_alloc_opts pt_opts = {};
        ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts,
                             &self->rma.pte[lac]);
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

    status = uct_cxi_iface_pte_enable(self, self->rma.pte[lac], &self->rx_eq);
    if (status != UCS_OK) {
        goto err_unmap_pte;
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
 * Slow path of uct_cxi_iface_tgt_post(): the first emit failed with \a ret, so
 * wait for room in the target command queue and submit \a cmd. A full queue is
 * transient (commands are rung as soon as emitted), and a lost command cannot
 * be recovered (a dropped SEARCH_AND_DELETE, repost or UNLINK would leave the
 * receive state wrong), so wait up to a timeout. Progress is single-threaded,
 * so command order is preserved.
 */
ucs_status_t uct_cxi_iface_tgt_post_wait(uct_cxi_iface_t *iface,
                                         const void *cmd, int ret)
{
    ucs_time_t deadline = ucs_get_time() +
                          ucs_time_from_sec(UCT_CXI_TGT_CMDQ_TIMEOUT_SEC);

    while (ret == -ENOSPC) {
        if (ucs_get_time() > deadline) {
            ucs_error("cxi target command queue stayed full for %.1f s",
                      UCT_CXI_TGT_CMDQ_TIMEOUT_SEC);
            return UCS_ERR_TIMED_OUT;
        }

        ucs_compiler_fence();
        ret = cxi_cq_emit_target(iface->tgt.cmdq, cmd);
    }

    if (ret != 0) {
        ucs_error("cxi target command emit failed: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    cxi_cq_ring(iface->tgt.cmdq);
    return UCS_OK;
}

/*
 * Enable \a pte (SETSTATE) and wait on \a eq for its STATE_CHANGE, up to
 * UCT_CXI_PTE_ENABLE_TIMEOUT_SEC. Other events read meanwhile are discarded:
 * this runs at open, before any traffic.
 */
ucs_status_t uct_cxi_iface_pte_enable(uct_cxi_iface_t *iface,
                                      struct cxil_pte *pte, uct_cxi_eq_t *eq)
{
    struct c_set_state_cmd ss       = {};
    ucs_time_t             deadline = ucs_get_time() +
                                      ucs_time_from_sec(
                                              UCT_CXI_PTE_ENABLE_TIMEOUT_SEC);
    const union c_event   *ev;
    int                    enabled  = 0;
    ucs_status_t           status;

    ss.command.opcode = C_CMD_TGT_SETSTATE;
    ss.ptlte_index    = pte->ptn;
    ss.ptlte_state    = C_PTLTE_ENABLED;

    status = uct_cxi_iface_tgt_post(iface, &ss);
    if (status != UCS_OK) {
        ucs_error("cxi PTE ptn=%u SETSTATE: %s", (unsigned)pte->ptn,
                  ucs_status_string(status));
        return status;
    }

    while (!enabled) {
        while ((ev = cxi_eq_get_event(eq->evtq)) != NULL) {
            if ((ev->hdr.event_type == C_EVENT_STATE_CHANGE) &&
                (ev->tgt_long.initiator.state_change.ptlte_state ==
                 C_PTLTE_ENABLED)) {
                enabled = 1;
            }
        }
        cxi_eq_ack_events(eq->evtq);

        if (!enabled && (ucs_get_time() > deadline)) {
            ucs_error("cxi PTE ptn=%u was not enabled within %.1f s",
                      (unsigned)pte->ptn, UCT_CXI_PTE_ENABLE_TIMEOUT_SEC);
            return UCS_ERR_TIMED_OUT;
        }
    }

    return UCS_OK;
}

/*
 * Append one PRIORITY LE for AM receive buffer \a buf_idx. buffer_id echoes in
 * every PUT, identifying the buffer. min_free auto-unlinks the buffer when less
 * than the largest message is left, so a linked buffer always fits the next
 * Put (a Put that does not fit fails with NO_SPACE; it is not tried on the next
 * buffer).
 */
static ucs_status_t
uct_cxi_iface_post_am_le(uct_cxi_iface_t *self, int buf_idx, int restart_seq)
{
    struct c_target_cmd le = {};
    ucs_status_t        status;

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
    le.min_free              = self->am.max_msg;
    le.ignore_bits           = UINT64_MAX;
    le.match_bits            = 0;

    status = uct_cxi_iface_tgt_post(self, &le);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_error("cxi AM LE APPEND buf %d: %s", buf_idx,
                  ucs_status_string(status));
        return status;
    }
    ucs_debug("cxi AM LE APPEND buf=%d ptn=%u start=0x%lx len=%zu restart_seq=%d",
             buf_idx, self->am.pte->ptn,
             (unsigned long)le.start, self->am.buf_size, restart_seq);
    return UCS_OK;
}

/*
 * Open the unrestricted AM PTE (long events, with valid rlength, mlength and
 * start) and post all receive buffers into the PRIORITY list.
 */
static ucs_status_t
uct_cxi_iface_open_am_pte(uct_cxi_iface_t *self, struct cxil_lni *lni)
{
    ucs_status_t status;
    int          ret;

    {
        /* en_flowctrl: a full EQ disables the PTE gracefully (accountable via
         * drop_count) instead of dropping events. AM's LEs raise real events,
         * so this is the PTE that needs it. */
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,   /* unrestricted (messaging) mode */
            .use_long_event = 1,   /* force 64-byte events with rlength/start */
            .en_flowctrl    = 1
        };
        ret = cxil_alloc_pte(lni, self->rx_eq.evtq, &pt_opts, &self->am.pte);
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

    status = uct_cxi_iface_pte_enable(self, self->am.pte, &self->rx_eq);
    if (status != UCS_OK) {
        goto err_unmap_pte;
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

/* mpool obj_init for the bcopy desc pool: precompute the IOVA of the data
 * area from the chunk's registration (IOVA(data) = iova_offset + data VA). */
static void uct_cxi_send_desc_init(uct_iface_h tl_iface, void *obj,
                                    uct_mem_h memh)
{
    uct_cxi_send_desc_t  *desc   = obj;
    uct_cxi_mem_handle_t *cxi_mh = (uct_cxi_mem_handle_t *)memh;

    desc->iova = cxi_mh->iova_offset + (uint64_t)(uintptr_t)(desc + 1);
    desc->lac  = cxi_mh->cxi_md->lac;
#ifndef UCT_CXI_DISABLE_FC
    desc->op.fc_slots = 0;
#endif
}

#ifndef UCT_CXI_DISABLE_FC
/* A pooled op starts out uncharged; the completion that consumes a charged
 * one clears it again (see uct_cxi_op_fc_take). */
static void uct_cxi_send_op_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
    ((uct_cxi_send_op_t *)obj)->fc_slots = 0;
}
#endif

/* op_pool: plain malloc/free. */
static ucs_mpool_ops_t uct_cxi_send_op_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
#ifndef UCT_CXI_DISABLE_FC
    .obj_init      = uct_cxi_send_op_init,
#else
    .obj_init      = NULL,
#endif
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

/* The largest AM we advertise (AM_MAX_ZCOPY), and the largest message of any
 * kind a receive buffer must hold (its min_free). */
static void uct_cxi_iface_set_am_limits(uct_cxi_iface_t *self,
                                        const uct_cxi_iface_config_t *config)
{
    size_t max_msg = ucs_max(config->am_max_zcopy, config->max_bcopy);

    if (max_msg > UCT_CXI_AM_MAX_MSG_LIMIT) {
        ucs_warn("cxi AM_MAX_ZCOPY=%zu / MAX_BCOPY=%zu exceed the %u bytes "
                 "that min_free can express: limiting the AM size to it",
                 config->am_max_zcopy, config->max_bcopy,
                 UCT_CXI_AM_MAX_MSG_LIMIT);
        max_msg = UCT_CXI_AM_MAX_MSG_LIMIT;
    }

    self->am.max_zcopy = ucs_min(config->am_max_zcopy, max_msg);
    self->am.max_msg   = max_msg;
}

/*
 * Number and size of the AM receive buffers. \a outstanding is the most bytes
 * peers may have sent and not had processed (active senders x byte window).
 *
 * Messages are placed back to back and a buffer retires once less than max_msg
 * is left, so each takes at least (buf_size - 8 - max_msg) bytes before it
 * retires. Events are processed in order and a buffer is reposted when its
 * retiring event is, so unprocessed bytes sit in the buffers after the one
 * being processed. Allow for those, the buffer being processed and one more
 * linked for the next message:
 *
 *    num_bufs = floor(outstanding / (buf_size - 8 - max_msg)) + 2
 */
static void uct_cxi_iface_size_am_ring(uct_cxi_iface_t *self,
                                       const uct_cxi_iface_config_t *config,
                                       size_t outstanding)
{
    size_t        max_msg  = self->am.max_msg;
    size_t        min_size = 2 * max_msg + sizeof(uint64_t);
    size_t        buf_size;
    unsigned long num_bufs;
    unsigned long needed;

    if (config->am_rx_buf_size != UCS_MEMUNITS_AUTO) {
        buf_size = config->am_rx_buf_size;
    } else {
        buf_size = ucs_max((size_t)UCT_CXI_AM_RX_BUF_SIZE_MIN,
                           UCT_CXI_AM_RX_BUF_PER_MSG * max_msg);
    }

    if (buf_size < min_size) {
        ucs_warn("cxi AM receive buffer size %zu is too small for %zu-byte "
                 "messages: using %zu", buf_size, max_msg, min_size);
        buf_size = min_size;
    }

    needed = outstanding / (buf_size - sizeof(uint64_t) - max_msg) + 2;

    if (config->am_rx_num_bufs == UCS_ULUNITS_AUTO) {
        num_bufs = needed;
    } else {
        num_bufs = config->am_rx_num_bufs;
        if (needed > num_bufs) {
            ucs_warn("cxi AM_RX_NUM_BUFS=%lu is below the %lu that "
                     "FC_ACTIVE_SENDERS peers at their full window need: "
                     "the ring can run out of buffers under load",
                     num_bufs, needed);
        }
    }

    if (num_bufs > UCT_CXI_AM_RX_NUM_BUFS_MAX) {
        ucs_warn("cxi AM receive ring wants %lu buffers, limited to %u",
                 num_bufs, UCT_CXI_AM_RX_NUM_BUFS_MAX);
        num_bufs = UCT_CXI_AM_RX_NUM_BUFS_MAX;
    }

    self->am.num_bufs = (unsigned)ucs_max(num_bufs, 2ul);
    self->am.buf_size = buf_size;
}

/* -------------------------------------------------------------------------
 * The credit windows: what flow control grants each peer, and, whether or not
 * it is on, what the receive rings and the RX EQ are sized for -- so that a run
 * without flow control has the buffers of one with it, and the two compare the
 * credit scheme alone.
 * -------------------------------------------------------------------------
 */

/* Window of one class in units, from \a byte_window: a multiple of
 * UCT_CXI_FC_WINDOW_GRAIN (as the CREP carries it), at least \a max_msg (or it
 * could never be sent), at most what the CREP can carry. */
static uint32_t uct_cxi_fc_unit_window(size_t byte_window, size_t max_msg,
                                       const char *knob, const char *what)
{
    const uint64_t grain     = UCT_CXI_FC_WINDOW_GRAIN;
    uint64_t       max_units = (UCT_CXI_FC_UNITS(max_msg) + grain - 1) / grain *
                               grain;
    uint64_t       unit_window = ((uint64_t)byte_window / UCT_CXI_FC_UNIT +
                                  grain - 1) / grain * grain;

    if (unit_window > UCT_CXI_FC_MAX_UNIT_WINDOW) {
        ucs_warn("cxi %s=%zu is more than a window can be: limiting it to "
                 "%zu", knob, byte_window,
                 (size_t)UCT_CXI_FC_MAX_UNIT_WINDOW * UCT_CXI_FC_UNIT);
        unit_window = UCT_CXI_FC_MAX_UNIT_WINDOW;
    }
    if (unit_window < max_units) {
        ucs_warn("cxi %s=%zu is smaller than the largest %s (%zu bytes): "
                 "raising it to %zu", knob, byte_window, what, max_msg,
                 (size_t)max_units * UCT_CXI_FC_UNIT);
        unit_window = max_units;
    }
    return (uint32_t)unit_window;
}

/*
 * The credit windows to grant each peer. Needed before the interface opens (the
 * rings and RX EQ are sized from them), so not part of uct_cxi_fc_init(). Each
 * byte window holds at least its class's largest message; \a tag_max_msg is 0
 * without tag offload.
 */
void uct_cxi_fc_windows(const uct_cxi_iface_config_t *config, size_t am_max_msg,
                        size_t tag_max_msg, uint32_t *slot_window_p,
                        uint32_t unit_window[UCT_CXI_FC_NUM_CLASSES])
{
    /* At least what the costliest message charges, or it could never be
     * sent. */
    *slot_window_p = ucs_max(UCT_CXI_FC_MAX_SLOTS,
                             ucs_min(config->fc_msg_window,
                                     UCT_CXI_FC_MAX_SLOT_WINDOW));
    unit_window[UCT_CXI_FC_AM] =
            uct_cxi_fc_unit_window(config->fc_byte_window, am_max_msg,
                                   "FC_BYTE_WINDOW", "Active Message");
    /* No tag matching, no pool for it. */
    unit_window[UCT_CXI_FC_TAG] = (tag_max_msg == 0) ? 0 :
            uct_cxi_fc_unit_window(config->fc_tag_byte_window, tag_max_msg,
                                   "FC_TAG_BYTE_WINDOW", "tag message");
}

/*
 * RX EQ depth. \a slot_credits is the most event slots peers may have
 * outstanding (active senders x slot window), \a tag_receives the most posted
 * tag receives.
 *
 * A message is charged the slots of the events it can leave until processed, so
 * they always fit; one that matches a posted receive is charged back at its ACK
 * and its events are the receive's (UCT_CXI_TAG_RECV_EVENTS each). Plus
 * reserved slots (PTE state changes, our own target commands), slack (events
 * are acknowledged in batches), and at least UCT_CXI_EQ_NUM_EVENTS for the
 * failure events of remote memory access.
 */
static unsigned
uct_cxi_iface_rx_eq_events(const uct_cxi_iface_config_t *config,
                           size_t slot_credits, size_t tag_receives)
{
    unsigned needed = ucs_max((size_t)UCT_CXI_EQ_NUM_EVENTS,
                              slot_credits +
                              tag_receives * UCT_CXI_TAG_RECV_EVENTS +
                              config->eq_reserved_slots + UCT_CXI_EQ_SLACK);

    if (config->eq_size == UINT_MAX) {
        return needed;
    }

    if (config->eq_size < needed) {
        ucs_warn("cxi EQ_SIZE=%u is below the %u events that "
                 "FC_ACTIVE_SENDERS peers at their full window need: the "
                 "RX queue can fill under load", config->eq_size, needed);
    }
    return config->eq_size;
}

UCS_CLASS_INIT_FUNC(uct_cxi_iface_t, uct_md_h md, uct_worker_h worker,
                    const uct_iface_params_t *params,
                    const uct_iface_config_t *tl_config)
{
    const uct_cxi_iface_config_t *config = ucs_derived_of(tl_config,
                                                           uct_cxi_iface_config_t);
    uct_cxi_md_t              *cxi_md   = ucs_derived_of(md, uct_cxi_md_t);
    struct cxil_lni           *lni      = cxi_md->cxi_lni;
    struct cxi_cq_alloc_opts   cq_opts;
    ucs_mpool_params_t         mp_params;
    ucs_status_t               status;
    int                        ret;
    unsigned                   op_max_bufs;
    unsigned                   desc_max_bufs;
    size_t                     msg_credits  = 0;
    size_t                     byte_credits = 0;
    size_t                     tag_byte_credits = 0;
    size_t                     tag_receives = 0;
    uint32_t                   slot_window  = 0;
    uint32_t                   unit_window[UCT_CXI_FC_NUM_CLASSES] = {};
    unsigned                   active_senders;

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

    /* Resolve the TX pool caps and both EQ depths. -1 (UINT_MAX) means unset:
     * a pool cap becomes half the default RX depth, EQ_SIZE and TX_EQ_SIZE
     * UCT_CXI_EQ_NUM_EVENTS; an explicit value is used exactly. TX_EQ_SIZE
     * also caps the sends in flight (tx.max_inflight). */
    uct_cxi_iface_set_am_limits(self, config);
    /* Rings and RX EQ are sized for the peers' windows with flow control on or
     * off, so the two compare the credit scheme alone. */
    active_senders = ucs_max(config->fc_active_senders, 1u);
    uct_cxi_fc_windows(config, self->am.max_msg,
                       uct_cxi_iface_tag_requested(config, params) ?
                               uct_cxi_tag_max_msg(config) : 0,
                       &slot_window, unit_window);
    msg_credits      = (size_t)active_senders * slot_window;
    byte_credits     = (size_t)active_senders * unit_window[UCT_CXI_FC_AM] *
                       UCT_CXI_FC_UNIT;
    tag_byte_credits = (size_t)active_senders * unit_window[UCT_CXI_FC_TAG] *
                       UCT_CXI_FC_UNIT;
    if (uct_cxi_iface_tag_requested(config, params)) {
        tag_receives = ucs_min(config->tag_max_outstanding,
                               (unsigned)UCT_CXI_TAG_MAX_OUTSTANDING_MAX);
    }

    {
        unsigned tx_eq_cfg = config->tx_eq_size;
        unsigned op_cfg    = config->op_mp.max_bufs;
        unsigned desc_cfg  = config->bcopy_mp.max_bufs;

        op_max_bufs   = (op_cfg == UINT_MAX) ?
                        ucs_max(UCT_CXI_EQ_NUM_EVENTS / 2, 1u) : op_cfg;
        desc_max_bufs = (desc_cfg == UINT_MAX) ?
                        ucs_max(UCT_CXI_EQ_NUM_EVENTS / 2, 1u) : desc_cfg;

        /* Only the RX queue is ever grown or has PTEs to recover; the TX
         * queue is fixed-size and reserves no slots for incoming traffic. */
        uct_cxi_eq_configure(&self->rx_eq, "rx",
                             uct_cxi_iface_rx_eq_events(config, msg_credits,
                                                     tag_receives),
                             config->eq_reserved_slots,
                             config->dynamic_eq_growth, config);

        if ((tx_eq_cfg != UINT_MAX) && (tx_eq_cfg <= UCT_CXI_TX_EQ_UNTRACKED)) {
            ucs_warn("cxi TX_EQ_SIZE=%u leaves no room for sends beyond the "
                     "%u slots reserved for get_short and error events; "
                     "using %u", tx_eq_cfg, UCT_CXI_TX_EQ_UNTRACKED,
                     UCT_CXI_TX_EQ_UNTRACKED + 1);
            tx_eq_cfg = UCT_CXI_TX_EQ_UNTRACKED + 1;
        }
        uct_cxi_eq_configure(&self->tx_eq, "tx",
                             (tx_eq_cfg == UINT_MAX) ? UCT_CXI_EQ_NUM_EVENTS :
                                                       tx_eq_cfg,
                             0, 0, config);

        /* configure() may round the depth up; derive the cap from what the
         * queue actually holds. */
        self->tx.max_inflight = self->tx_eq.num_events -
                                UCT_CXI_TX_EQ_UNTRACKED;
    }

    /* PTE flow-control recovery config, resolved once here (setup time,
     * not the hot path) — see cxi_iface.h / iface_progress(). */
    self->eq_flap_limit        = config->eq_flap_limit;
    self->eq_flap_window       = ucs_time_from_sec(config->eq_flap_window);
    memset(&self->am.fc, 0, sizeof(self->am.fc));

    /* Wait object (epoll fd for event-driven progress). */
    ret = cxil_alloc_wait_obj(lni, &self->wait_obj);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_wait_obj failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* Steps 3-5: event queues (ring buffer, pinning, hardware queue). */
    status = uct_cxi_eq_init(&self->rx_eq, lni, self->wait_obj);
    if (status != UCS_OK) {
        goto err_destroy_wait_obj;
    }

    status = uct_cxi_eq_init(&self->tx_eq, lni, self->wait_obj);
    if (status != UCS_OK) {
        goto err_cleanup_rx_eq;
    }

    /* TX communication profile. */
    ret = cxil_alloc_cp(lni, cxi_md->vni,
                        CXI_TC_BEST_EFFORT, CXI_TC_TYPE_DEFAULT, &self->tx.cp);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cp vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_cleanup_tx_eq;
    }

    /* TX command queue. */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    cq_opts.flags = CXI_CQ_IS_TX;
    cq_opts.lcid  = self->tx.cp->lcid;
    ret = cxil_alloc_cmdq(lni, self->tx_eq.evtq, &cq_opts, &self->tx.cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tx failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_cp;
    }

    /* Target command queue (LE management). */
    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CMDQ_DEPTH;
    ret = cxil_alloc_cmdq(lni, self->rx_eq.evtq, &cq_opts, &self->tgt.cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq tg failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tx_cmdq;
    }

    /* Domain (VNI + PID). */
    ret = cxil_alloc_domain(lni, cxi_md->vni, C_PID_ANY, &self->domain);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_domain vni %u failed: %s",
                  (unsigned)cxi_md->vni, strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_tg_cmdq;
    }

    self->match_id = CXI_MATCH_ID(cxi_md->pid_bits, self->domain->pid,
                                  cxi_md->device.nid);

    /* Open all RMA PTEs up front (see the file comment). */
    {
        uint8_t lac;
        for (lac = 0; lac < UCT_CXI_MAX_LACS; lac++) {
            status = uct_cxi_iface_open_rma_pte(self, lni, lac);
            if (status != UCS_OK) {
                goto err_rma_ptes;
            }
        }
    }

    /* Send-op pool for zcopy completions. max_elems = op_max_bufs makes
     * exhaustion return UCS_ERR_NO_RESOURCE before outstanding ops exceed the
     * EQ depth. */
    self->tx.outstanding = 0;
#ifndef UCT_CXI_DISABLE_FC
    self->tx.credit_block = 0;
#endif
    kh_init_inplace(uct_cxi_zombie_ep_hash, &self->tx.zombie_eps);
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

    /* bcopy desc pool of DMA-registered bounce buffers: one chunk is
     * UCT_CXI_CMDQ_DEPTH descs (about 2 MB), capped at desc_max_bufs. */
    self->tx.max_bcopy = config->max_bcopy;
    {
        uct_iface_mpool_config_t desc_mp_config = config->bcopy_mp;
        /* ucs_mpool_init() needs max_elems >= elems_per_chunk: clamp
         * BCOPY_BUFS_GROW and the fallback to a small BCOPY_MAX_BUFS. 0 keeps
         * "transport picks". */
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

    /* get_short scratch buffer, separate from the iface struct so NIC writes
     * stay off its hot fields. */
    /* Page-align the scratch buffer: cxil_map's IOVA is page-granular, so
     * cmd.local_addr must be at the page start. */
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

    /* AM receive buffers: one page-aligned allocation and one cxil_map, so
     * iova_offset + VA is each slice's exact IOVA. */
    uct_cxi_iface_size_am_ring(self, config, byte_credits);
    ucs_info("cxi AM ring: %u buffers of %zu bytes, min_free %zu; RX EQ %u "
             "events", self->am.num_bufs, self->am.buf_size, self->am.max_msg,
             self->rx_eq.num_events);
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

    /* Hardware tag offload: a no-op (tag.pte stays NULL) unless UCP supplied
     * both HW_TM callbacks and UCX_CXI_TAG_ENABLE != no. */
    status = uct_cxi_iface_open_tag_pte(self, lni, config, params, msg_credits,
                                        tag_byte_credits);
    if (status != UCS_OK) {
        goto err_am_pte;
    }

    /* Rendezvous source-exposure PTE, opened only if tag offload is enabled.
     * self->rdzv is zeroed here unconditionally: no other call site does, and
     * a stale heap value made close unmap garbage when HW_TM was not requested
     * (e.g. ucx_info). */
    memset(&self->rdzv, 0, sizeof(self->rdzv));
    self->rdzv.ptn = -1;
    if (self->tag.enabled) {
        status = uct_cxi_iface_open_rdzv_pte(self, lni);
        if (status != UCS_OK) {
            goto err_tag_pte;
        }
    }

#ifndef UCT_CXI_DISABLE_FC
    /* Connected-endpoint flow control: per-peer state and the control channel
     * its handshake runs on. */
    status = uct_cxi_fc_init(self, config, slot_window, unit_window);
    if (status != UCS_OK) {
        goto err_rdzv_pte;
    }
    status = uct_cxi_ctrl_open(self, config, lni);
    if (status != UCS_OK) {
        goto err_fc;
    }
#endif

    ucs_info("cxi iface open %p nid 0x%x pid %u ptn %u pid_bits %u "
             "max_lacs %u",
             self, cxi_md->device.nid, self->domain->pid,
             self->rma.pte[0]->ptn, (unsigned)cxi_md->pid_bits,
             (unsigned)UCT_CXI_MAX_LACS);
    return UCS_OK;

#ifndef UCT_CXI_DISABLE_FC
err_fc:
    uct_cxi_fc_cleanup(self);
#endif
err_rdzv_pte:
    uct_cxi_iface_close_rdzv_pte(self);
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
err_cleanup_tx_eq:
    uct_cxi_eq_cleanup(&self->tx_eq);
err_cleanup_rx_eq:
    uct_cxi_eq_cleanup(&self->rx_eq);
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

    uct_cxi_eq_abort_resize(&self->rx_eq);
    uct_cxi_eq_abort_resize(&self->tx_eq);

    ucs_arbiter_cleanup(&self->tx.arbiter);

    /* Destroyed eps with sends in flight are freed by their last completion,
     * which will never be processed now: free them here. */
    if (kh_size(&self->tx.zombie_eps) > 0) {
        uint64_t zombie;

        ucs_debug("cxi iface %p closing while %u destroyed endpoint(s) still "
                  "have sends in flight", self,
                  (unsigned)kh_size(&self->tx.zombie_eps));
        kh_foreach_key(&self->tx.zombie_eps, zombie, {
            ucs_free((void*)(uintptr_t)zombie);
        });
    }
    kh_destroy_inplace(uct_cxi_zombie_ep_hash, &self->tx.zombie_eps);

#ifndef UCT_CXI_DISABLE_FC
    /* Opened last, closed first. */
    uct_cxi_ctrl_close(self);
    uct_cxi_fc_cleanup(self);
#endif

    /* Close RDZV, then TAG, then AM (reverse of open); no-ops without tag
     * offload. */
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

    uct_cxi_eq_cleanup(&self->tx_eq);
    uct_cxi_eq_cleanup(&self->rx_eq);

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
    iface_attr->cap.am.max_zcopy      = iface->am.max_zcopy;
    iface_attr->cap.am.opt_zcopy_align = sizeof(uint64_t);
    iface_attr->cap.am.align_mtu      = 1;
    iface_attr->cap.am.max_iov        = 1;

    if (iface->tag.enabled) {
        iface_attr->cap.flags |= UCT_IFACE_FLAG_TAG_EAGER_SHORT |
                                 UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
                                 UCT_IFACE_FLAG_TAG_EAGER_ZCOPY;

        iface_attr->cap.tag.recv.min_recv       = 0;
        /* Bounded by the posted receive (UCP asserts a rendezvous fits), not
         * by the overflow ring. */
        iface_attr->cap.tag.recv.max_zcopy      = UINT32_MAX;
        iface_attr->cap.tag.recv.max_iov        = 1; /* no send/recv SG anywhere
                                                          in this transport */
        iface_attr->cap.tag.recv.max_outstanding = iface->tag.max_outstanding;

        /* No header reservation, unlike AM (see cxi_tag.c). */
        iface_attr->cap.tag.eager.max_short = C_MAX_IDC_PAYLOAD_UNR;
        iface_attr->cap.tag.eager.max_bcopy = ucs_min(iface->tag.max_msg,
                                                      iface->tx.max_bcopy);
        iface_attr->cap.tag.eager.max_zcopy = iface->tag.max_msg;
        iface_attr->cap.tag.eager.max_iov   = 1;

        /* max_hdr must be >= sizeof(ucp_tag_offload_unexp_rndv_hdr_t) (17): UCP
         * asserts it and packs that header into every offloaded rendezvous
         * send, so less would disable offloaded rendezvous. 256 leaves margin.
         * max_zcopy and max_iov are bounded by c_full_dma_cmd's request_len and
         * the single-iov restriction. */
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
 * Issue SETSTATE(ENABLED) for \a pte if it is DISABLED, within a per-PTE flap
 * limit. Called once the RX EQ has drained (need_to_drain), not on a raw drop:
 * re-enabling into a full EQ re-triggers the disable. The state is queried
 * (cxil_pte_status), not inferred from a STATE_CHANGE, which can itself be lost
 * under EQ pressure.
 */
static void
uct_cxi_iface_pte_recover(uct_cxi_iface_t *iface, struct cxil_pte *pte,
                          uct_cxi_pte_fc_t *fc)
{
    struct cxi_pte_status  pte_s = {};
    struct c_set_state_cmd ss    = {};
    ucs_time_t             now;
    ucs_status_t           status;

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

    status = uct_cxi_iface_tgt_post(iface, &ss);
    if (ucs_unlikely(UCS_STATUS_IS_ERR(status))) {
        ucs_warn("cxi PTE ptn=%u: SETSTATE post failed: %s", pte->ptn,
                 ucs_status_string(status));
        return;
    }
    ucs_debug("cxi PTE ptn=%u: recovering (flap %u/%u), SETSTATE ENABLED "
             "drop_count=%u", pte->ptn, fc->flap_count, iface->eq_flap_limit,
             pte_s.drop_count);
}

/*
 * uct_cxi_iface_recover_ptes — check every PTE that flow control can disable
 * (AM, tag, rendezvous) and recover any found DISABLED.  Called once the EQ
 * has been drained enough (eq.need_to_drain reaching 0), not per-drop.
 */
static void uct_cxi_iface_recover_ptes(uct_cxi_iface_t *iface)
{
    uct_cxi_iface_pte_recover(iface, iface->am.pte, &iface->am.fc);
    uct_cxi_iface_pte_recover(iface, iface->tag.pte, &iface->tag.fc);
    uct_cxi_iface_pte_recover(iface, iface->rdzv.pte, &iface->rdzv.fc);
}

/* The PTE and recovery state matching a STATE_CHANGE's ptlte_index, or NULL. */
static uct_cxi_pte_fc_t *
uct_cxi_iface_pte_by_index(uct_cxi_iface_t *iface, uint16_t ptlte_index,
                           struct cxil_pte **pte_p)
{
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
    *pte_p = NULL;
    return NULL;
}


/* A PTE changed state (flow control disabled it, or it was re-enabled). Slow
 * path, out of line to keep the inlined dispatch small. */
static UCS_F_NOINLINE void
uct_cxi_iface_handle_state_change(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq,
                                  const union c_event *event)
{
    /* A DISABLED report is either a fresh NIC-initiated disable (rc OK) or the
     * rejection (rc C_RC_NO_MATCH) of our own SETSTATE(ENABLED) because
     * drop_count moved after our cxil_pte_status() read. Only rc tells them
     * apart (sc_reason is meaningless on a rejection). */
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
        /* Our SETSTATE was rejected (drop_count raced): not EQ pressure, so
         * retry at once with a fresh read. */
        struct cxil_pte  *pte;
        uct_cxi_pte_fc_t *fc = uct_cxi_iface_pte_by_index(
                iface, ptlte_index, &pte);
        if (fc != NULL) {
            uct_cxi_iface_pte_recover(iface, pte, fc);
        }
    } else if (ptlte_state == C_PTLTE_DISABLED) {
        if (sc_reason == C_SC_FC_EQ_FULL) {
            /* Disabled for EQ capacity: affects every flow-control PTE on the
             * RX EQ (AM, tag, rendezvous). Recovery waits for the EQ to drain
             * (need_to_drain, uct_cxi_iface_poll_rx()). */
            if (eq->need_to_drain == 0) {
                eq->need_to_drain = (eq->num_events * eq->drain_pct) / 100;
            }
        } else if ((iface->am.pte != NULL) &&
                   (ptlte_index == iface->am.pte->ptn)) {
            /* Disabled on the AM PTE for matching-resource exhaustion (all ring
             * buffers full), independent of EQ fill: gate AM sends
             * (am.fc.exhausted) and recover now, since draining frees no
             * buffers. */
            iface->am.fc.exhausted = 1;
            uct_cxi_iface_pte_recover(iface, iface->am.pte,
                                      &iface->am.fc);
        }
    } else if (ptlte_state == C_PTLTE_ENABLED) {
        /* Re-enabled: clear AM matching-resource exhaustion (the drain
         * countdown clears itself). */
        if ((iface->am.pte != NULL) &&
            (ptlte_index == iface->am.pte->ptn)) {
            iface->am.fc.exhausted = 0;
        }
    }
}

void uct_cxi_tx_emit_failed(const void *obj, const char *what, int ret)
{
    ucs_error("cxi %p %s emit failed: %d", obj, what, ret);
}

/* Log a failed TX completion; out of line to keep the completion path small. */
static UCS_F_NOINLINE void
uct_cxi_iface_tx_error(uct_cxi_iface_t *iface, const union c_event *event,
                       uct_cxi_ep_t *ep)
{
    ucs_error("cxi TX event %d error: rc=%d ep %p",
              (int)event->hdr.event_type, cxi_event_rc(event), ep);
    if (cxi_event_rc(event) == C_RC_ENTRY_NOT_FOUND &&
        iface->am.pte != NULL) {
        struct cxi_pte_status pte_s = {};
        if (cxil_pte_status(iface->am.pte, &pte_s) == 0) {
            ucs_error("cxi AM PTE state=%u drop_count=%u ule_count=%u",
                      pte_s.state, pte_s.drop_count, pte_s.ule_count);
        }
    }
}

/*
 * A Put the NIC could not place in an AM buffer (rc != OK, mlength 0, no
 * message). The sender sees the failure in its ACK and takes its credits back,
 * so there is nothing to deliver or return. The usual cause is a message longer
 * than what is left of the buffer it matched.
 */
static UCS_F_NOINLINE void
uct_cxi_iface_am_put_failed(uct_cxi_iface_t *iface, const union c_event *event)
{
    int buf_idx = (int)event->tgt_long.buffer_id;

    ucs_error("cxi AM Put failed: rc=%d buf=%d rlength=%u mlength=%u, "
              "message dropped", (int)event->tgt_long.return_code, buf_idx,
              (unsigned)event->tgt_long.rlength,
              (unsigned)event->tgt_long.mlength);

    /* The buffer's fate does not depend on how this Put went. */
    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        uct_cxi_iface_post_am_le(iface, buf_idx, 1);
    }
}

/* Account one completed send against its ep (op-tracked or a tagged short).
 * \a slots, \a cls and \a units are its flow-control charge (0 slots:
 * uncharged). */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_ep_tx_done(uct_cxi_iface_t *iface, const union c_event *event,
                         uct_cxi_ep_t *ep, ucs_status_t status, unsigned cls,
                         unsigned slots, unsigned units)
{
    if (ucs_unlikely(status != UCS_OK)) {
        uct_cxi_iface_tx_error(iface, event, ep);
#ifndef UCT_CXI_DISABLE_FC
        /* The message did not reach the target's software, so the target will
         * never hand back what it cost: take it back. */
        if (slots != 0) {
            uct_cxi_fc_refund(iface, ep, cls, slots, units);
        }
#endif
    }
#ifndef UCT_CXI_DISABLE_FC
    else if ((slots != 0) && (cls == UCT_CXI_FC_TAG) &&
             (event->init_short.ptl_list == C_PTL_LIST_PRIORITY)) {
        /* A tag message that matched a posted receive is not tracked by the
         * target (the receive's own slots pay for its events), so nothing will
         * be handed back: take the charge back now. One that went to the
         * overflow list is returned by the target when it is done with it.
         * (Hardware reports the same list to both sides: see test_cxi_tag_ack.)
         */
        uct_cxi_fc_reclaim(iface, ep->peer, cls, slots, units);
    }
#endif
    /* Latch the worst status of ops draining under a pending flush (the first
     * failure sticks). */
    if (ep->flush_comp != NULL) {
        uct_completion_update_status(ep->flush_comp, status);
    }
    ep->outstanding--;
    iface->tx.outstanding--;
    if (ep->outstanding == 0 && ep->flush_comp != NULL) {
        uct_invoke_completion(ep->flush_comp, UCS_OK);
        ep->flush_comp = NULL;
    }
    ucs_trace("cxi TX event %d rc=%d ep %p outstanding=%u",
              (int)event->hdr.event_type, cxi_event_rc(event), ep,
              ep->outstanding);
}

/* The flow-control charge of an op, cleared as read so a pooled op never looks
 * charged. Returns its event slots (0: uncharged). */
static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_op_fc_take(uct_cxi_send_op_t *op, unsigned *cls_p, unsigned *units_p)
{
#ifndef UCT_CXI_DISABLE_FC
    unsigned slots = op->fc_slots;

    *cls_p       = op->fc_class;
    *units_p     = op->fc_units;
    op->fc_slots = 0;
    return slots;
#else
    *cls_p   = 0;
    *units_p = 0;
    return 0;
#endif
}

/* Free an ep that uct_ep_destroy() left alive for its in-flight sends, once the
 * last one has completed. */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_ep_release(uct_cxi_iface_t *iface, uct_cxi_ep_t *ep)
{
    khiter_t iter;

    if (ucs_unlikely(ep->destroyed) && (ep->outstanding == 0)) {
        iter = kh_get(uct_cxi_zombie_ep_hash, &iface->tx.zombie_eps,
                      (uintptr_t)ep);
        ucs_assert(iter != kh_end(&iface->tx.zombie_eps));
        kh_del(uct_cxi_zombie_ep_hash, &iface->tx.zombie_eps, iter);
        ucs_free(ep);
    }
}

/*
 * What each EQ holds. TX: ACK and REPLY of commands issued with it as cmd.eq.
 * RX: everything raised by the data-path PTEs, plus the REPLY of Gets issued
 * from an event handler (address read, software rendezvous Get), which point at
 * the RX queue to need no TX slot, and of the NIC's own rendezvous Gets.
 * Control: the control PTE's arrivals and control send completions. The queues
 * are polled and dispatched separately, so none pays for another's events.
 */
#define UCT_CXI_TX_EVENT_MASK  (UCS_BIT(C_EVENT_ACK) | UCS_BIT(C_EVENT_REPLY))

/* Rare paths of dispatch and polling, out of line to keep the inlined fast
 * paths small. */

/* An event the queue \a eq has no handler for. */
static UCS_F_NOINLINE void
uct_cxi_iface_event_unhandled(const uct_cxi_eq_t *eq,
                              const union c_event *event)
{
    ucs_info("cxi iface_progress: unhandled %s event type %d rc=%d", eq->name,
             (int)event->hdr.event_type, cxi_event_rc(event));
}

static UCS_F_NOINLINE void
uct_cxi_iface_stray_put_overflow(const union c_event *event)
{
    ucs_info("cxi C_EVENT_PUT_OVERFLOW: ptl_list=%d am_id=%u "
             "mlength=%u start=0x%lx remote_offset=0x%lx rc=%d",
             (int)event->tgt_long.ptl_list,
             (unsigned)(event->tgt_long.match_bits & 0x1f),
             (unsigned)event->tgt_long.mlength,
             (unsigned long)event->tgt_long.start,
             (unsigned long)event->tgt_long.remote_offset,
             cxi_event_rc(event));
}

static UCS_F_NOINLINE void
uct_cxi_iface_stray_unlink(const union c_event *event)
{
    /* Auto-unlink is signaled by auto_unlinked on the triggering PUT, where the
     * repost happens; a genuine UNLINK is a manual one (teardown), with
     * nothing to repost. */
    ucs_debug("cxi AM LE C_EVENT_UNLINK buf=%d (manual)",
              (int)event->tgt_long.buffer_id);
}

/* \a eq lost events because it was full. */
static UCS_F_NOINLINE void
uct_cxi_iface_eq_drops(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq)
{
    ucs_error("cxi %s EQ drop detected: events lost (EQ full)", eq->name);

    /* Only the RX queue has PTEs to recover: the TX queue is bounded by the
     * sends in flight, so losing events there is a bug, not pressure. */
    if ((eq == &iface->rx_eq) && (eq->need_to_drain == 0)) {
        eq->need_to_drain = (eq->num_events * eq->drain_pct) / 100;
    }
    cxi_eq_ack_drops(eq->evtq);
}

/*
 * Drain countdown after a drop: each processed event counts (no hardware
 * query). Events are often smaller than the 64 bytes eq.num_events assumes, so
 * this only under-counts freed room, the safe direction. At zero, recover the
 * PTEs found disabled; re-enabling on every drop would re-trigger the disable.
 */
static UCS_F_NOINLINE void
uct_cxi_iface_rx_drain_step(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq)
{
    if (--eq->need_to_drain == 0) {
        uct_cxi_iface_recover_ptes(iface);
    }
}

/*
 * TX queue: each event completes a send, accounted by its user_ptr: an IDC
 * short by its ep alone (the charge is in the pointer), anything else by a send
 * op, whose ep is never NULL here.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_handle_tx_event(uct_cxi_iface_t *iface,
                              const union c_event *event)
{
    uint64_t user_ptr;

    if (ucs_unlikely(!(UCS_BIT(event->hdr.event_type) &
                       UCT_CXI_TX_EVENT_MASK))) {
        uct_cxi_iface_event_unhandled(&iface->tx_eq, event);
        return;
    }

    /* Every command that reports on the TX queue carries a user_ptr. */
    user_ptr = event->init_short.user_ptr;
    ucs_assert(user_ptr != 0);

    if (user_ptr & UCT_CXI_USER_PTR_SHORT) {
        /* IDC short, tracked by its ep alone (no op) -- see
         * uct_cxi_idc_track_hdr, which also left its cost in the top byte. */
        uct_cxi_ep_t *ep = (uct_cxi_ep_t *)(uintptr_t)(
                user_ptr & UCT_CXI_USER_PTR_PTR_MASK &
                ~(UCT_CXI_USER_PTR_SHORT | UCT_CXI_USER_PTR_TAG));
        unsigned      cls;
        unsigned      slots;

        if (user_ptr & UCT_CXI_USER_PTR_TAG) {
            cls   = UCT_CXI_FC_TAG;
            slots = UCT_CXI_FC_SLOTS_TAG_EAGER;
        } else {
            cls   = UCT_CXI_FC_AM;
            slots = UCT_CXI_FC_SLOTS_AM;
        }
        if (!(user_ptr & UCT_CXI_USER_PTR_CREDITED)) {
            slots = 0;
        }

        uct_cxi_iface_ep_tx_done(
                iface, event, ep, uct_cxi_rc_to_status(cxi_event_rc(event)),
                cls, slots,
                (unsigned)((user_ptr >> UCT_CXI_USER_PTR_UNITS_SHIFT) &
                           UCT_CXI_USER_PTR_UNITS_MASK));
        uct_cxi_iface_ep_release(iface, ep);
    } else {
        uct_cxi_send_op_t *op = (uct_cxi_send_op_t *)(uintptr_t)user_ptr;
        uct_cxi_ep_t      *ep = op->ep;
        ucs_status_t       status = uct_cxi_rc_to_status(cxi_event_rc(event));
        unsigned           cls;
        unsigned           units;

        /* ACK: a restricted PUT or DMA send is done; REPLY: GET data returned.
         * Ops without an ep complete on the RX queue and never get here. */
        ucs_assert(ep != NULL);

        {
            unsigned slots = uct_cxi_op_fc_take(op, &cls, &units);

            uct_cxi_iface_ep_tx_done(iface, event, ep, status, cls, slots,
                                     units);
        }

        if (op->handler != NULL) {
            op->handler(op, status); /* bcopy: handler owns comp + mpool_put */
        } else {
            if (op->comp != NULL) {
                uct_invoke_completion(op->comp, status);
            }
            ucs_mpool_put(op);     /* zcopy / short */
        }
        uct_cxi_iface_ep_release(iface, ep);
    }
}

/*
 * RX, C_EVENT_PUT on the AM PTE: deliver the message, return its sender's
 * credits, and repost the buffer if this Put retired it.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_rx_am(uct_cxi_iface_t *iface, const union c_event *event)
{
#ifndef UCT_CXI_DISABLE_FC
    uct_cxi_peer_t *peer = NULL;

    /* Piggybacked credits are for what we send to its sender; its own cost is
     * handed back once processed. A sender without flow control has no peer
     * record. */
    if (ucs_likely(iface->fc.enabled)) {
        peer = uct_cxi_fc_rx_peer(
                iface, event->tgt_long.initiator.initiator.process);
        if (ucs_unlikely((peer != NULL) &&
                         (event->tgt_long.match_bits & UCT_CXI_FC_PB_VALID))) {
            uct_cxi_fc_apply_piggyback(iface, peer, event->tgt_long.match_bits);
        }
    }
#endif

    {
        /* start is the absolute IOVA of the first byte the NIC wrote, in the
         * buffer registered at iova_offset + its address. */
        void     *data = (void *)(uintptr_t)(event->tgt_long.start -
                                             iface->am.rx_mh.iova_offset);
        uint32_t  len  = event->tgt_long.mlength;

        if (ucs_unlikely(event->tgt_long.match_bits &
                         UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG)) {
            /* A transport-internal rendezvous-header announce
             * (UCT_CXI_RNDV_HDR_ANNOUNCE_FLAG), not a user AM: it does not go
             * to uct_iface_invoke_am(). */
            uct_cxi_iface_handle_rndv_hdr_announce(iface, event, data, len);
        } else {
            if (ucs_unlikely(event->tgt_long.match_bits &
                             UCT_CXI_AM_HDR_FLAG)) {
                uint64_t hdr = event->tgt_long.header_data;

                memcpy((uint8_t *)data - sizeof(uint64_t), &hdr,
                       sizeof(uint64_t));
                data = (uint8_t *)data - sizeof(uint64_t);
                len += sizeof(uint64_t);
            }

            uct_iface_invoke_am(&iface->super,
                                (uint8_t)(event->tgt_long.match_bits & 0x1f),
                                data, len, 0);
        }
    }

#ifndef UCT_CXI_DISABLE_FC
    /* Processed: return the sender's credits (its charge was the length before
     * any header was prepended). */
    if (peer != NULL) {
        uct_cxi_fc_rx_done(iface, peer, UCT_CXI_FC_AM, UCT_CXI_FC_SLOTS_AM,
                           event->tgt_long.mlength);
    }
#endif

    if (ucs_unlikely(event->tgt_long.auto_unlinked)) {
        /* This Put retired the buffer (min_free). EQ delivery is ordered, so it
         * is the buffer's last Put: repost it here. */
        uct_cxi_iface_post_am_le(iface, (int)event->tgt_long.buffer_id, 1);
    }
}

/*
 * RX, C_EVENT_PUT: a message landed on one of our PTEs. The tag PTE reports
 * both LE populations as PUT (ptl_list tells them apart); a failed Put on any
 * other PTE reports its rc; the rest are Active Messages.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_rx_put(uct_cxi_iface_t *iface, const union c_event *event)
{
    if (event->tgt_long.ptlte_index == iface->tag.ptn) {
        /* Tag receive. A direct-matched rendezvous Put's eager-attached prefix
         * also lands here (PRIORITY, rendezvous == 1) beside its
         * C_EVENT_RENDEZVOUS: route by that flag, not just ptl_list. */
        if (event->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) {
            uct_cxi_iface_tag_handle_ovf_arrival(iface, event);
        } else if (event->tgt_long.rendezvous) {
            uct_cxi_iface_tag_handle_rdzv_match(iface, event);
        } else {
            uct_cxi_iface_tag_handle_eager_match(iface, event);
        }
    } else if (ucs_unlikely(event->tgt_long.return_code != C_RC_OK)) {
        uct_cxi_iface_am_put_failed(iface, event);
    } else {
        uct_cxi_iface_rx_am(iface, event);
    }
}

/*
 * RX, C_EVENT_REPLY: the completion of a Get issued from an event handler: the
 * NIC's own rendezvous Get (its user_ptr is a bit-packed struct
 * cxi_rdzv_user_ptr, see uct_cxi_iface_tag_handle_rdzv_reply) or one of ours,
 * whose op has no ep (tag receives belong to the interface).
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_rx_reply(uct_cxi_iface_t *iface, const union c_event *event)
{
    if (event->init_short.rendezvous) {
        uct_cxi_iface_tag_handle_rdzv_reply(iface, event);
    } else {
        uct_cxi_send_op_t *op =
                (uct_cxi_send_op_t *)(uintptr_t)event->init_short.user_ptr;

        ucs_assert(op != NULL);
        ucs_assert(op->ep == NULL);
        op->handler(op, uct_cxi_rc_to_status(cxi_event_rc(event)));
    }
}

/*
 * RX, C_EVENT_PUT_OVERFLOW on the tag PTE: our SEARCH_AND_DELETE's "found"
 * outcome (UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID), or the delayed match of a real
 * receive (handled like a direct match, routed by the event's rendezvous flag).
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_rx_put_overflow(uct_cxi_iface_t *iface,
                              const union c_event *event)
{
    if (ucs_unlikely(event->tgt_long.ptlte_index != iface->tag.ptn)) {
        uct_cxi_iface_stray_put_overflow(event);
    } else if (event->tgt_long.buffer_id ==
               UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID) {
        uct_cxi_iface_tag_handle_search_delete_found(iface, event);
    } else if (event->tgt_long.rendezvous) {
        uct_cxi_iface_tag_handle_rdzv_match(iface, event);
    } else {
        uct_cxi_iface_tag_handle_eager_match(iface, event);
    }
}

/*
 * RX queue: an event raised by one of our PTEs, or the completion of a Get
 * issued from a handler. The common one, a message landing, is tested first.
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_handle_rx_event(uct_cxi_iface_t *iface,
                              const union c_event *event)
{
    if (ucs_likely(event->hdr.event_type == C_EVENT_PUT)) {
        uct_cxi_iface_rx_put(iface, event);
        return;
    }

    switch (event->hdr.event_type) {
    case C_EVENT_REPLY:
        uct_cxi_iface_rx_reply(iface, event);
        break;
    case C_EVENT_PUT_OVERFLOW:
        uct_cxi_iface_rx_put_overflow(iface, event);
        break;
    case C_EVENT_RENDEZVOUS:
        /* Direct-matched rendezvous Put, always on the priority list; joins
         * tag_handle_rdzv_match's three-event accounting. */
        if (ucs_likely(event->tgt_long.ptlte_index == iface->tag.ptn)) {
            uct_cxi_iface_tag_handle_rdzv_match(iface, event);
        } else {
            uct_cxi_iface_event_unhandled(&iface->rx_eq, event);
        }
        break;
    case C_EVENT_GET:
        /* A peer's Get read from our exposed rendezvous catch-all LE -- the
         * send side of a rendezvous transfer completing. */
        if (ucs_likely(event->tgt_long.ptlte_index == iface->rdzv.ptn)) {
            uct_cxi_iface_tag_handle_rdzv_get(iface, event);
        } else {
            uct_cxi_iface_event_unhandled(&iface->rx_eq, event);
        }
        break;
    case C_EVENT_SEARCH:
        if (event->tgt_long.ptlte_index != iface->tag.ptn) {
            uct_cxi_iface_event_unhandled(&iface->rx_eq, event);
        } else if (event->tgt_long.buffer_id ==
                   UCT_CXI_TAG_SEARCH_DELETE_BUFFER_ID) {
            uct_cxi_iface_tag_handle_search_delete_missed(iface, event);
        } else if (event->tgt_long.buffer_id == UCT_CXI_TAG_FENCE_BUFFER_ID) {
            uct_cxi_iface_tag_fence_done(iface, event);
        } else {
            uct_cxi_iface_event_unhandled(&iface->rx_eq, event);
        }
        break;
    case C_EVENT_UNLINK:
        if (event->tgt_long.ptlte_index == iface->tag.ptn) {
            uct_cxi_iface_tag_handle_unlink(iface, event);
        } else {
            uct_cxi_iface_stray_unlink(event);
        }
        break;
    case C_EVENT_STATE_CHANGE:
        uct_cxi_iface_handle_state_change(iface, &iface->rx_eq, event);
        break;
    case C_EVENT_EQ_SWITCH:
        /* The last event hardware writes to the old buffer of a resize
         * (uct_cxi_iface_eq_grow_start): switch to the new one. */
        uct_cxi_iface_eq_grow_complete(iface, &iface->rx_eq);
        break;
    default:
        uct_cxi_iface_event_unhandled(&iface->rx_eq, event);
        break;
    }
}

/* Each queue is drained for at most eq->max_poll events per call, so a flood
 * cannot keep the loop from the checks after it. */

/* Poll the RX queue: events, then the drop, preemptive growth and ack
 * bookkeeping. */
static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_iface_poll_rx(uct_cxi_iface_t *iface)
{
    uct_cxi_eq_t *eq = &iface->rx_eq;
    unsigned      n;

    for (n = 0; n < eq->max_poll; n++) {
        const union c_event *event = cxi_eq_get_event(eq->evtq);

        if (event == NULL) {
            break;
        }

        uct_cxi_iface_handle_rx_event(iface, event);

        /* Draining back down after a drop. */
        if (ucs_unlikely(eq->need_to_drain > 0)) {
            uct_cxi_iface_rx_drain_step(iface, eq);
        }
    }

    if (ucs_unlikely(cxi_eq_get_drops(eq->evtq))) {
        uct_cxi_iface_eq_drops(iface, eq);
    }

    /* Preemptive growth: a cheap timestamp-gated check
     * (uct_cxi_iface_eq_grow_start), independent of the reactive drop handling
     * above. */
    if (eq->grow.enabled && !eq->grow.resizing) {
        struct c_eq_status eq_status;

        if (cxi_eq_get_status(eq->evtq, &eq_status) &&
            eq_status.thld_sts &&
            (cxi_eq_status_fill_level(eq->evtq, &eq_status) >=
                    eq->grow.thresh_pct)) {
            uct_cxi_iface_eq_grow_start(iface, eq);
        }
    }

    if (n > 0) {
        cxi_eq_ack_events(eq->evtq);
    }

    return n;
}

/* Poll the TX queue. It is bounded by the sends in flight and never grown, and
 * has no PTEs to recover. */
static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_iface_poll_tx(uct_cxi_iface_t *iface)
{
    uct_cxi_eq_t *eq = &iface->tx_eq;
    unsigned      n;

    for (n = 0; n < eq->max_poll; n++) {
        const union c_event *event = cxi_eq_get_event(eq->evtq);

        if (event == NULL) {
            break;
        }

        uct_cxi_iface_handle_tx_event(iface, event);
    }

    if (ucs_unlikely(cxi_eq_get_drops(eq->evtq))) {
        uct_cxi_iface_eq_drops(iface, eq);
    }

    if (n > 0) {
        cxi_eq_ack_events(eq->evtq);
    }

    return n;
}

#ifndef UCT_CXI_DISABLE_FC
/*
 * Control queue: an arrival at the control PTE or the completion of a control
 * message. Bounded, never grown, and nothing to recover (the PTE is never
 * disabled: a message that finds no room is refused).
 */
static UCS_F_ALWAYS_INLINE void
uct_cxi_iface_handle_ctrl_event(uct_cxi_iface_t *iface,
                                const union c_event *event)
{
    if (ucs_likely(event->hdr.event_type == C_EVENT_PUT)) {
        uct_cxi_iface_handle_ctrl_msg(iface, event);
    } else if (event->hdr.event_type == C_EVENT_ACK) {
        uct_cxi_iface_ctrl_tx_done(iface,
                                   (uct_cxi_ctrl_req_t *)(uintptr_t)
                                           event->init_short.user_ptr,
                                   event);
    } else {
        uct_cxi_iface_event_unhandled(&iface->ctrl.eq, event);
    }
}

static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_iface_poll_ctrl(uct_cxi_iface_t *iface)
{
    uct_cxi_eq_t *eq = &iface->ctrl.eq;
    unsigned      n;

    for (n = 0; n < eq->max_poll; n++) {
        const union c_event *event = cxi_eq_get_event(eq->evtq);

        if (event == NULL) {
            break;
        }

        uct_cxi_iface_handle_ctrl_event(iface, event);
    }

    if (ucs_unlikely(cxi_eq_get_drops(eq->evtq))) {
        uct_cxi_iface_eq_drops(iface, eq);
    }

    if (n > 0) {
        cxi_eq_ack_events(eq->evtq);
    }

    return n;
}
#endif

static unsigned uct_cxi_iface_progress(uct_iface_h tl_iface)
{
    uct_cxi_iface_t *iface = ucs_derived_of(tl_iface, uct_cxi_iface_t);
    unsigned         n     = 0;

#ifndef UCT_CXI_DISABLE_FC
    /* The control channel first: it depends on nothing in the data path, and
     * its handshakes and credits are what let that path go on. */
    if (ucs_likely(iface->ctrl.enabled)) {
        n = uct_cxi_iface_poll_ctrl(iface);

        /* A grant that could not be sent goes now that completions freed room;
         * its receiver may be unable to send until it arrives. */
        if (ucs_unlikely(!ucs_list_is_empty(&iface->fc.grants))) {
            uct_cxi_fc_flush_grants(iface);
        }

        /* Handshake timers (resends and deadlines). A reply that just arrived
         * has cancelled its resend; the wheel only has timers while something
         * waits. */
        if (ucs_unlikely(!ucs_twheel_is_empty(&iface->fc.twheel))) {
            ucs_twheel_sweep(&iface->fc.twheel, ucs_get_time());
        }
    }
#endif

    /* Each queue gets its own EQ_MAX_POLL budget, so neither a receive flood
     * nor a burst of completions can starve the other. */
    n += uct_cxi_iface_poll_rx(iface);
    n += uct_cxi_iface_poll_tx(iface);

    /* Retry sends queued by uct_ep_pending_add(): completions may have freed
     * resources. A cheap no-op when the arbiter is empty. */
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
