/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI control channel: a portal table entry, an event queue and a command
 * queue of their own, over which the transport talks to the same transport on
 * other nodes (today the flow-control handshake and credit grants, see
 * cxi_fc.h). Nothing here depends on the clients: a control message is a
 * zero-payload send to the control PTE of a peer, and everything it says
 * travels in its match bits and header data.
 *
 * The channel shares nothing with the data path. Its PTE lists one
 * zero-length entry that accepts every message, so a message needs no
 * buffer, and is bound to the control event queue, so control traffic can
 * neither fill the receive queue of the data path nor be refused because it
 * is full. Its sends use their own command queue and report to the same
 * event queue, so they neither wait for nor take a place of the sends of the
 * data path. The event queue holds the messages that arrive and the
 * completions of the messages sent, and the slots of the completions are
 * reserved: a message that arrives can only be refused (the sender is told),
 * never cost a completion.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"

/* Built with the flow control, its only client (see Makefile.am). */
#ifndef UCT_CXI_DISABLE_FC

#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>

#include <string.h>


/* Plain host memory: control requests are only ever read by software. */
static ucs_mpool_ops_t uct_cxi_ctrl_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL,
    .obj_str       = NULL
};


/*
 * Enable the control PTE: SETSTATE, then wait for the state change event that
 * confirms it.
 */
static ucs_status_t uct_cxi_ctrl_enable_pte(uct_cxi_iface_t *iface)
{
    uct_cxi_ctrl_t         *ctrl     = &iface->ctrl;
    struct c_set_state_cmd  ss       = {};
    ucs_time_t              deadline = ucs_get_time() +
                                       ucs_time_from_sec(
                                               UCT_CXI_TGT_CMDQ_TIMEOUT_SEC);
    const union c_event    *ev;
    int                     enabled  = 0;
    int                     ret;

    ss.command.opcode = C_CMD_TGT_SETSTATE;
    ss.ptlte_index    = ctrl->pte->ptn;
    ss.ptlte_state    = C_PTLTE_ENABLED;

    ret = cxi_cq_emit_target(iface->tgt.cmdq, &ss);
    if (ret != 0) {
        ucs_error("cxi CTRL SETSTATE: %d", ret);
        return UCS_ERR_IO_ERROR;
    }
    cxi_cq_ring(iface->tgt.cmdq);

    while (!enabled) {
        while ((ev = cxi_eq_get_event(ctrl->eq.evtq)) != NULL) {
            if ((ev->hdr.event_type == C_EVENT_STATE_CHANGE) &&
                (ev->tgt_long.initiator.state_change.ptlte_state ==
                 C_PTLTE_ENABLED)) {
                enabled = 1;
            }
        }
        cxi_eq_ack_events(ctrl->eq.evtq);

        if (!enabled && (ucs_get_time() > deadline)) {
            ucs_error("cxi CTRL PTE was not enabled within %.1f s",
                      UCT_CXI_TGT_CMDQ_TIMEOUT_SEC);
            return UCS_ERR_TIMED_OUT;
        }
    }

    return UCS_OK;
}

/* Allocate and enable the control PTE, and post its one list entry. */
static ucs_status_t uct_cxi_ctrl_open_pte(uct_cxi_iface_t *iface,
                                          struct cxil_lni *lni)
{
    uct_cxi_ctrl_t      *ctrl = &iface->ctrl;
    struct c_target_cmd  le   = {};
    ucs_status_t         status;
    int                  ret;

    {
        /* No flow control: the only thing that can refuse a message here is
         * a full event queue, and then the sender is told and sends it
         * again. The PTE is never disabled, so recovery has nothing to do
         * for it, and the messages that recovery itself needs can always
         * travel. */
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,
            .use_long_event = 1,
            .en_flowctrl    = 0
        };
        ret = cxil_alloc_pte(lni, ctrl->eq.evtq, &pt_opts, &ctrl->pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte CTRL: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    ret = cxil_map_pte(ctrl->pte, iface->domain, (int)UCT_CXI_PTE_CTRL, false,
                       &ctrl->pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte CTRL: %s", strerror(-ret));
        goto err_destroy_pte;
    }

    status = uct_cxi_ctrl_enable_pte(iface);
    if (status != UCS_OK) {
        goto err_unmap_pte;
    }

    /* One persistent, zero-length list entry that accepts everything. */
    le.command.opcode          = C_CMD_TGT_APPEND;
    le.ptl_list                = C_PTL_LIST_PRIORITY;
    le.ptlte_index             = ctrl->pte->ptn;
    le.op_put                  = 1;
    le.use_once                = 0;
    le.manage_local            = 0;
    le.event_link_disable      = 1;
    le.event_unlink_disable    = 1;
    le.unexpected_hdr_disable  = 1;
    le.match_id                = CXI_MATCH_ID_ANY;
    le.ignore_bits             = UINT64_MAX;
    le.match_bits              = 0;
    le.start                   = 0;
    le.length                  = 0;
    status = uct_cxi_iface_tgt_post(iface, &le);
    if (status != UCS_OK) {
        ucs_error("cxi CTRL LE APPEND: %s", ucs_status_string(status));
        goto err_unmap_pte;
    }

    ucs_debug("cxi CTRL PTE ptn %u enabled", (unsigned)ctrl->pte->ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(ctrl->pte_map);
    ctrl->pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(ctrl->pte);
    ctrl->pte = NULL;
    return UCS_ERR_IO_ERROR;
}

ucs_status_t uct_cxi_ctrl_open(uct_cxi_iface_t *iface,
                               const uct_cxi_iface_config_t *config,
                               struct cxil_lni *lni)
{
    uct_cxi_ctrl_t           *ctrl = &iface->ctrl;
    struct cxi_cq_alloc_opts  cq_opts;
    ucs_mpool_params_t        mp_params;
    ucs_status_t              status;
    int                       ret;

    memset(ctrl, 0, sizeof(*ctrl));

    /* Without flow control on this run there is no control PTE: a peer's CREQ
     * finds none and marks this interface as a plain connectionless peer. */
    if (!iface->fc.enabled) {
        return UCS_OK;
    }

    ctrl->max_inflight = UCT_CXI_CTRL_MAX_INFLIGHT;

    /* The completions of the messages sent have slots of their own, which
     * the messages that arrive may not use. */
    uct_cxi_eq_configure(&ctrl->eq, "ctrl",
                         (config->ctrl_eq_size == UINT_MAX) ?
                                 UCT_CXI_CTRL_EQ_NUM_EVENTS :
                                 ucs_max(config->ctrl_eq_size,
                                         2 * ctrl->max_inflight),
                         ctrl->max_inflight, 0, config);
    status = uct_cxi_eq_init(&ctrl->eq, lni, iface->wait_obj);
    if (status != UCS_OK) {
        return status;
    }

    memset(&cq_opts, 0, sizeof(cq_opts));
    cq_opts.count = UCT_CXI_CTRL_CMDQ_DEPTH;
    cq_opts.flags = CXI_CQ_IS_TX;
    cq_opts.lcid  = iface->tx.cp->lcid;
    ret = cxil_alloc_cmdq(lni, ctrl->eq.evtq, &cq_opts, &ctrl->cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq ctrl failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_cleanup_eq;
    }

    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_ctrl_req_t);
    mp_params.elems_per_chunk = ucs_min(32u, ctrl->max_inflight);
    mp_params.max_elems       = ctrl->max_inflight;
    mp_params.ops             = &uct_cxi_ctrl_mpool_ops;
    mp_params.name            = "cxi-ctrl-req";
    status = ucs_mpool_init(&mp_params, &ctrl->req_pool);
    if (status != UCS_OK) {
        goto err_destroy_cmdq;
    }

    status = uct_cxi_ctrl_open_pte(iface, lni);
    if (status != UCS_OK) {
        goto err_cleanup_pool;
    }

    ctrl->enabled = 1;
    return UCS_OK;

err_cleanup_pool:
    ucs_mpool_cleanup(&ctrl->req_pool, 1);
err_destroy_cmdq:
    cxil_destroy_cmdq(ctrl->cmdq);
err_cleanup_eq:
    uct_cxi_eq_cleanup(&ctrl->eq);
    ctrl->eq.evtq = NULL;
    return status;
}

void uct_cxi_ctrl_close(uct_cxi_iface_t *iface)
{
    uct_cxi_ctrl_t *ctrl = &iface->ctrl;
    int             ret;

    ctrl->enabled = 0;
    if (ctrl->eq.evtq == NULL) {
        return;
    }

    if (ctrl->pte_map != NULL) {
        ret = cxil_unmap_pte(ctrl->pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte CTRL failed: %s", strerror(-ret));
        }
        ctrl->pte_map = NULL;
    }
    if (ctrl->pte != NULL) {
        ret = cxil_destroy_pte(ctrl->pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte CTRL failed: %s", strerror(-ret));
        }
        ctrl->pte = NULL;
    }

    ret = cxil_destroy_cmdq(ctrl->cmdq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_cmdq ctrl failed: %s", strerror(-ret));
    }

    /* A request still in flight when the interface closes is normal (its
     * completion is simply never processed): don't report it as a leak. */
    ucs_mpool_cleanup(&ctrl->req_pool, 0);
    uct_cxi_eq_cleanup(&ctrl->eq);
    ctrl->eq.evtq = NULL;
}

/*
 * uct_cxi_ctrl_send -- send one zero-payload control message to \a peer's
 * control PTE. It takes one of the ctrl->max_inflight places until its
 * completion, so UCS_ERR_NO_RESOURCE if there is none free or the command
 * queue is full, and the caller just tries again later (a GRANT from the list
 * of waiting ones, a CREQ from its timer, a CREP when the requester sends its
 * CREQ again).
 */
ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                               unsigned type, uint64_t match_bits,
                               uint64_t header_data, uint32_t grant_slots,
                               const uint32_t *grant_units)
{
    uct_cxi_ctrl_t     *ctrl    = &iface->ctrl;
    unsigned            pid_bits = uct_cxi_iface_md(iface)->pid_bits;
    uct_cxi_ctrl_req_t *req;
    union c_fab_addr    dfa;
    uint8_t             idx_ext;
    int                 ret;

    if (ctrl->outstanding >= ctrl->max_inflight) {
        return UCS_ERR_NO_RESOURCE;
    }

    req = ucs_mpool_get(&ctrl->req_pool);
    if (req == NULL) {
        return UCS_ERR_NO_RESOURCE;
    }
    req->peer        = peer;
    req->type        = type;
    req->grant_slots = grant_slots;
    if (grant_units != NULL) {
        memcpy(req->grant_units, grant_units, sizeof(req->grant_units));
    } else {
        memset(req->grant_units, 0, sizeof(req->grant_units));
    }
    cxi_build_dfa(CXI_MATCH_ID_EP(pid_bits, peer->key),
                  CXI_MATCH_ID_PID(pid_bits, peer->key), pid_bits,
                  UCT_CXI_PTE_CTRL, &dfa, &idx_ext);

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 0;
        cstate.initiator           = iface->match_id;
        cstate.index_ext           = idx_ext;
        cstate.eq                  = ctrl->eq.evtq->eqn;

        ret = cxi_cq_emit_c_state(ctrl->cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa         = dfa;
        hdr.match_bits  = match_bits;
        hdr.header_data = header_data;
        hdr.user_ptr    = (uint64_t)(uintptr_t)req;

        ret = cxi_cq_emit_idc_msg(ctrl->cmdq, &hdr, hdr.data, 0);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(ctrl->cmdq);
    ctrl->outstanding++;
    return UCS_OK;
}

#endif /* UCT_CXI_DISABLE_FC */
