/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI control channel: a PTE, event queue and command queue of their own for
 * messages between transports (today the flow-control handshake and credit
 * grants, see cxi_fc.h). A control message is a zero-payload send whose
 * content travels in its match bits and header data.
 *
 * The control EQ holds arrivals and send completions. Slots for the
 * completions are reserved, so an arrival can be refused but never costs a
 * completion.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cxi_iface.h"

#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>

#include <string.h>

/* Built with the flow control, its only client (see Makefile.am). */
#ifndef UCT_CXI_DISABLE_FC

/* Allocate and enable the control PTE, and post its one list entry. */
static ucs_status_t
uct_cxi_ctrl_open_pte(uct_cxi_iface_t *iface, struct cxil_lni *lni)
{
    uct_cxi_ctrl_t *ctrl             = &iface->ctrl;
    struct c_target_cmd le           = {};
    struct cxi_pt_alloc_opts pt_opts = {
        .is_matching    = 1,
        .use_long_event = 1
    };
    ucs_status_t status;
    int ret;

    /* en_flowctrl stays off: a full EQ refuses the message and the sender
     * resends, so the PTE is never disabled. */
    ret = cxil_alloc_pte(lni, ctrl->eq.evtq, &pt_opts, &ctrl->pte);
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

    status = uct_cxi_iface_pte_enable(iface, ctrl->pte, &ctrl->eq);
    if (status != UCS_OK) {
        goto err_unmap_pte;
    }

    /* One persistent, zero-length list entry that accepts everything. */
    le.command.opcode         = C_CMD_TGT_APPEND;
    le.ptl_list               = C_PTL_LIST_PRIORITY;
    le.ptlte_index            = ctrl->pte->ptn;
    le.op_put                 = 1;
    le.event_link_disable     = 1;
    le.event_unlink_disable   = 1;
    le.unexpected_hdr_disable = 1;
    le.match_id               = CXI_MATCH_ID_ANY;
    le.ignore_bits            = UINT64_MAX;
    status                    = uct_cxi_iface_tgt_post(iface, &le);
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
    uct_cxi_ctrl_t *ctrl = &iface->ctrl;
    struct cxi_cq_alloc_opts cq_opts;
    ucs_mpool_params_t mp_params;
    ucs_status_t status;
    int ret;

    memset(ctrl, 0, sizeof(*ctrl));

    /* FC_ENABLE=n: no control PTE, so a peer's CREQ finds none and marks this
     * interface LEGACY. */
    if (!iface->fc.enabled) {
        return UCS_OK;
    }

    ctrl->max_inflight = UCT_CXI_CTRL_MAX_INFLIGHT;

    /* One reserved slot per message in flight, for its completion. */
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
    ret           = cxil_alloc_cmdq(lni, ctrl->eq.evtq, &cq_opts, &ctrl->cmdq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_cmdq ctrl failed: %s", strerror(-ret));
        status = UCS_ERR_IO_ERROR;
        goto err_cleanup_eq;
    }

    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_ctrl_req_t);
    mp_params.elems_per_chunk = ucs_min(32u, ctrl->max_inflight);
    mp_params.max_elems       = ctrl->max_inflight;
    mp_params.ops             = &uct_cxi_host_mpool_ops;
    mp_params.name            = "cxi-ctrl-req";
    status                    = ucs_mpool_init(&mp_params, &ctrl->req_pool);
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
    int ret;

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

    /* Requests still in flight at close are expected, not leaks. */
    ucs_mpool_cleanup(&ctrl->req_pool, 0);
    uct_cxi_eq_cleanup(&ctrl->eq);
    ctrl->eq.evtq = NULL;
}

/*
 * Send a zero-payload control message to \a peer's control PTE.
 * UCS_ERR_NO_RESOURCE if the channel is full; the caller retries later.
 */
ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                               unsigned type, uint64_t match_bits,
                               uint64_t header_data, uint32_t grant_slots,
                               const uint32_t *grant_units)
{
    uct_cxi_ctrl_t *ctrl       = &iface->ctrl;
    struct c_cstate_cmd cstate = {};
    struct c_idc_msg_hdr hdr   = {};
    uct_cxi_ctrl_req_t *req;
    union c_fab_addr dfa;
    unsigned pid_bits;
    uint8_t idx_ext;
    int ret;

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
    pid_bits = uct_cxi_iface_md(iface)->pid_bits;
    cxi_build_dfa(CXI_MATCH_ID_EP(pid_bits, peer->key),
                  CXI_MATCH_ID_PID(pid_bits, peer->key), pid_bits,
                  UCT_CXI_PTE_CTRL, &dfa, &idx_ext);

    cstate.event_send_disable = 1;
    cstate.initiator          = iface->match_id;
    cstate.index_ext          = idx_ext;
    cstate.eq                 = ctrl->eq.evtq->eqn;
    ret                       = cxi_cq_emit_c_state(ctrl->cmdq, &cstate);
    if (ucs_unlikely(ret != 0)) {
        goto err_put_req;
    }

    hdr.dfa         = dfa;
    hdr.match_bits  = match_bits;
    hdr.header_data = header_data;
    hdr.user_ptr    = (uint64_t)(uintptr_t)req;
    ret             = cxi_cq_emit_idc_msg(ctrl->cmdq, &hdr, hdr.data, 0);
    if (ucs_unlikely(ret != 0)) {
        goto err_put_req;
    }

    cxi_cq_ring(ctrl->cmdq);
    ctrl->outstanding++;
    return UCS_OK;

err_put_req:
    ucs_mpool_put(req);
    return UCS_ERR_NO_RESOURCE;
}

#endif /* UCT_CXI_DISABLE_FC */
