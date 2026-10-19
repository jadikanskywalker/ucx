/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI connected-endpoint flow control: peer records and the control channel
 * handshake. See cxi_fc.h for the protocol.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"
#include "cxi_ep.h"

/* Normally only built when flow control is enabled (see Makefile.am); the
 * guard keeps a build that merely defines UCT_CXI_DISABLE_FC working too. */
#ifndef UCT_CXI_DISABLE_FC

#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>

#include <string.h>


/* Plain host memory: control requests are only ever read by software. */
static ucs_mpool_ops_t uct_cxi_fc_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init      = NULL,
    .obj_cleanup   = NULL,
    .obj_str       = NULL
};


/* -------------------------------------------------------------------------
 * Interface-level state
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_fc_init(uct_cxi_iface_t *iface,
                             const uct_cxi_iface_config_t *config)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    ucs_mpool_params_t  mp_params;

    memset(fc, 0, sizeof(*fc));
    fc->enabled         = config->fc_enable;
    fc->ctrl.ptn        = UINT16_MAX; /* matches no PTE until one is opened */
    fc->msg_window      = config->fc_msg_window;
    fc->unit_window     = (uint32_t)ucs_min(config->fc_byte_window /
                                            UCT_CXI_FC_UNIT, UINT32_MAX);
    fc->connect_timeout = ucs_time_from_sec(config->fc_connect_timeout);

    /* Random per interface instance, so a peer can tell a restarted process
     * from the one it handshook with before. Never 0. */
    fc->epoch = (uint32_t)ucs_generate_uuid((uintptr_t)iface);
    if (fc->epoch == 0) {
        fc->epoch = 1;
    }

    kh_init_inplace(uct_cxi_peer_hash, &fc->peers);
    ucs_list_head_init(&fc->connecting);

    ucs_mpool_params_reset(&mp_params);
    mp_params.elem_size       = sizeof(uct_cxi_ctrl_req_t);
    mp_params.elems_per_chunk = UCT_CXI_CTRL_SLOTS;
    mp_params.max_elems       = UCT_CXI_CTRL_SLOTS;
    mp_params.ops             = &uct_cxi_fc_mpool_ops;
    mp_params.name            = "cxi-ctrl-req";
    return ucs_mpool_init(&mp_params, &fc->ctrl_req_pool);
}

void uct_cxi_fc_cleanup(uct_cxi_iface_t *iface)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    uct_cxi_peer_t     *peer;

    kh_foreach_value(&fc->peers, peer, {
        ucs_free(peer);
    });
    kh_destroy_inplace(uct_cxi_peer_hash, &fc->peers);

    /* A control request still in flight when the interface closes is normal
     * (its completion is simply never processed), so don't report it as a
     * leak. */
    ucs_mpool_cleanup(&fc->ctrl_req_pool, 0);
}


/* -------------------------------------------------------------------------
 * Control PTE
 * -------------------------------------------------------------------------
 */

ucs_status_t uct_cxi_iface_open_ctrl_pte(uct_cxi_iface_t *iface,
                                         struct cxil_lni *lni)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    const union c_event *ev;
    struct c_target_cmd  le = {};
    ucs_status_t         status;
    int                  ret;

    if (!fc->enabled) {
        return UCS_OK;
    }

    {
        /* en_flowctrl: when the receive event queue is full the PTE disables
         * itself and the sender sees C_RC_PT_DISABLED, instead of the event
         * being lost -- the only way this PTE can refuse a message, since its
         * list entry holds no buffer. */
        struct cxi_pt_alloc_opts pt_opts = {
            .is_matching    = 1,
            .use_long_event = 1,
            .en_flowctrl    = 1
        };
        ret = cxil_alloc_pte(lni, iface->rx_eq.evtq, &pt_opts, &fc->ctrl.pte);
    }
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_pte CTRL: %s", strerror(-ret));
        return UCS_ERR_IO_ERROR;
    }

    ret = cxil_map_pte(fc->ctrl.pte, iface->domain, (int)UCT_CXI_PTE_CTRL,
                       false, &fc->ctrl.pte_map);
    if (ret != 0) {
        ucs_error("cxi cxil_map_pte CTRL: %s", strerror(-ret));
        goto err_destroy_pte;
    }

    /* Transition the PTE DISABLED -> ENABLED; spin for the STATE_CHANGE. */
    {
        struct c_set_state_cmd ss = {};
        bool                   enabled = false;

        ss.command.opcode = C_CMD_TGT_SETSTATE;
        ss.ptlte_index    = fc->ctrl.pte->ptn;
        ss.ptlte_state    = C_PTLTE_ENABLED;

        ret = cxi_cq_emit_target(iface->tgt.cmdq, &ss);
        if (ret != 0) {
            ucs_error("cxi CTRL SETSTATE: %d", ret);
            goto err_unmap_pte;
        }
        cxi_cq_ring(iface->tgt.cmdq);

        while (!enabled) {
            while ((ev = cxi_eq_get_event(iface->rx_eq.evtq)) != NULL) {
                if (ev->hdr.event_type == C_EVENT_STATE_CHANGE &&
                    ev->tgt_long.initiator.state_change.ptlte_state
                            == C_PTLTE_ENABLED) {
                    enabled = true;
                }
            }
            cxi_eq_ack_events(iface->rx_eq.evtq);
        }
    }

    /* One persistent, zero-length list entry that accepts everything. */
    le.command.opcode          = C_CMD_TGT_APPEND;
    le.ptl_list                = C_PTL_LIST_PRIORITY;
    le.ptlte_index             = fc->ctrl.pte->ptn;
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

    fc->ctrl.ptn = fc->ctrl.pte->ptn;
    ucs_debug("cxi CTRL PTE ptn %u enabled", fc->ctrl.ptn);
    return UCS_OK;

err_unmap_pte:
    cxil_unmap_pte(fc->ctrl.pte_map);
    fc->ctrl.pte_map = NULL;
err_destroy_pte:
    cxil_destroy_pte(fc->ctrl.pte);
    fc->ctrl.pte = NULL;
    return UCS_ERR_IO_ERROR;
}

void uct_cxi_iface_close_ctrl_pte(uct_cxi_iface_t *iface)
{
    uct_cxi_fc_iface_t *fc = &iface->fc;
    int                 ret;

    fc->ctrl.ptn = UINT16_MAX;
    if (fc->ctrl.pte_map != NULL) {
        ret = cxil_unmap_pte(fc->ctrl.pte_map);
        if (ret != 0) {
            ucs_warn("cxi cxil_unmap_pte CTRL failed: %s", strerror(-ret));
        }
        fc->ctrl.pte_map = NULL;
    }
    if (fc->ctrl.pte != NULL) {
        ret = cxil_destroy_pte(fc->ctrl.pte);
        if (ret != 0) {
            ucs_warn("cxi cxil_destroy_pte CTRL failed: %s", strerror(-ret));
        }
        fc->ctrl.pte = NULL;
    }
}


/* -------------------------------------------------------------------------
 * Peers
 * -------------------------------------------------------------------------
 */

uct_cxi_peer_t *uct_cxi_peer_get(uct_cxi_iface_t *iface, uint32_t nid,
                                 uint32_t pid)
{
    uct_cxi_md_t   *md  = uct_cxi_iface_md(iface);
    uint32_t        key = CXI_MATCH_ID(md->pid_bits, pid, nid);
    uct_cxi_peer_t *peer;
    khiter_t        iter;
    int             ret;

    iter = kh_get(uct_cxi_peer_hash, &iface->fc.peers, key);
    if (iter != kh_end(&iface->fc.peers)) {
        return kh_value(&iface->fc.peers, iter);
    }

    peer = ucs_calloc(1, sizeof(*peer), "cxi peer");
    if (peer == NULL) {
        return NULL;
    }

    peer->key   = key;
    peer->nid   = nid;
    peer->pid   = pid;
    peer->state = UCT_CXI_PEER_DOWN;
    ucs_list_head_init(&peer->connecting);
    cxi_build_dfa(nid, pid, md->pid_bits, UCT_CXI_PTE_CTRL, &peer->dfa_ctrl,
                  &peer->dfa_ctrl_idx_ext);

    iter = kh_put(uct_cxi_peer_hash, &iface->fc.peers, key, &ret);
    if (ret < 0) {
        ucs_free(peer);
        return NULL;
    }
    kh_value(&iface->fc.peers, iter) = peer;
    return peer;
}

static uct_cxi_peer_t *uct_cxi_peer_lookup(uct_cxi_iface_t *iface,
                                           uint32_t key)
{
    khiter_t iter = kh_get(uct_cxi_peer_hash, &iface->fc.peers, key);

    return (iter == kh_end(&iface->fc.peers)) ?
           NULL : kh_value(&iface->fc.peers, iter);
}

/* A handshake is over (completed, failed, or not needed): stop resending. */
static void uct_cxi_peer_connected(uct_cxi_peer_t *peer, unsigned state)
{
    peer->state = state;
    if (!ucs_list_is_empty(&peer->connecting)) {
        ucs_list_del(&peer->connecting);
        ucs_list_head_init(&peer->connecting);
    }
}


/* -------------------------------------------------------------------------
 * Control messages
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ctrl_send -- send one zero-payload control message to \a peer's
 * control PTE, from the control request pool: UCS_ERR_NO_RESOURCE when all
 * UCT_CXI_CTRL_SLOTS are in flight or the command queue is full, and the
 * caller just tries again later. Control messages are not subject to the data
 * send cap -- they have their own slice of the TX queue.
 */
static ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface,
                                      uct_cxi_peer_t *peer, unsigned type,
                                      uint64_t match_bits, uint64_t header_data)
{
    uct_cxi_ctrl_req_t  *req;
    int                  ret;

    req = ucs_mpool_get(&iface->fc.ctrl_req_pool);
    if (req == NULL) {
        return UCS_ERR_NO_RESOURCE;
    }
    req->peer = peer;
    req->type = type;

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 0;
        cstate.initiator           = iface->match_id;
        cstate.index_ext           = peer->dfa_ctrl_idx_ext;
        uct_cxi_idc_track_cstate(&cstate, iface);

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa         = peer->dfa_ctrl;
        hdr.match_bits  = match_bits;
        hdr.header_data = header_data;
        hdr.user_ptr    = (uint64_t)(uintptr_t)req | UCT_CXI_USER_PTR_CTRL;

        ret = cxi_cq_emit_idc_msg(iface->tx.cmdq, &hdr, hdr.data, 0);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(req);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    return UCS_OK;
}

void uct_cxi_iface_ctrl_tx_done(uct_cxi_iface_t *iface, uct_cxi_ctrl_req_t *req,
                                const union c_event *event)
{
    int rc = cxi_event_rc(event);

    if (ucs_unlikely(rc != C_RC_OK)) {
        if ((rc == C_RC_PTLTE_NOT_FOUND) && (req->type == UCT_CXI_CTRL_CREQ) &&
            ((req->peer->state == UCT_CXI_PEER_DOWN) ||
             (req->peer->state == UCT_CXI_PEER_CREQ_SENT))) {
            /* The target has no control PTE: it does not do flow control. */
            ucs_debug("cxi peer nid 0x%x pid %u has no control channel, "
                      "treating it as a legacy peer", req->peer->nid,
                      req->peer->pid);
            uct_cxi_peer_connected(req->peer, UCT_CXI_PEER_LEGACY);
        } else {
            /* A CREQ is resent until answered and a lost CREP is answered
             * by the next CREQ, so nothing to do here. */
            ucs_debug("cxi control message %u to nid 0x%x pid %u failed: rc=%d",
                      req->type, req->peer->nid, req->peer->pid, rc);
        }
    }

    ucs_mpool_put(req);
}

void uct_cxi_iface_handle_ctrl_msg(uct_cxi_iface_t *iface,
                                   const union c_event *event)
{
    uct_cxi_md_t   *md      = uct_cxi_iface_md(iface);
    uint64_t        mb      = event->tgt_long.match_bits;
    uint64_t        hd      = event->tgt_long.header_data;
    uint32_t        process = event->tgt_long.initiator.initiator.process;
    uct_cxi_peer_t *peer;

    if (ucs_unlikely(UCT_CXI_CTRL_VER(mb) != UCT_CXI_CTRL_VERSION)) {
        ucs_debug("cxi ignoring control message with version %u",
                  UCT_CXI_CTRL_VER(mb));
        return;
    }

    switch (UCT_CXI_CTRL_TYPE(mb)) {
    case UCT_CXI_CTRL_CREQ:
        /* The requester's identity is the event's initiator: create its
         * record if this is the first we hear of it (without starting a
         * handshake of our own: each direction is independent). */
        peer = uct_cxi_peer_get(iface, CXI_MATCH_ID_EP(md->pid_bits, process),
                                CXI_MATCH_ID_PID(md->pid_bits, process));
        if (peer == NULL) {
            ucs_error("cxi no memory for a peer record, dropping CREQ");
            return;
        }
        peer->rx_epoch = (uint32_t)hd;

        /* Fire and forget: if this reply is lost, the requester resends its
         * CREQ and gets another. */
        (void)uct_cxi_ctrl_send(
                iface, peer, UCT_CXI_CTRL_CREP,
                UCT_CXI_CTRL_MATCH(UCT_CXI_CTRL_CREP, iface->fc.epoch,
                                   (uint32_t)hd),
                ((uint64_t)iface->fc.msg_window << 32) | iface->fc.unit_window);
        break;

    case UCT_CXI_CTRL_CREP:
        peer = uct_cxi_peer_lookup(iface, process);
        if ((peer == NULL) ||
            ((peer->state != UCT_CXI_PEER_DOWN) &&
             (peer->state != UCT_CXI_PEER_CREQ_SENT))) {
            ucs_debug("cxi ignoring unexpected CREP from initiator 0x%x",
                      process);
            return;
        }
        if (UCT_CXI_CTRL_ECHO(mb) != iface->fc.epoch) {
            ucs_debug("cxi ignoring CREP answering another incarnation");
            return;
        }
        peer->remote_epoch = UCT_CXI_CTRL_EPOCH24(mb);
        peer->msg_window   = (uint32_t)(hd >> 32);
        peer->unit_window  = (uint32_t)hd;
        uct_cxi_peer_connected(peer, UCT_CXI_PEER_UP);
        ucs_debug("cxi peer nid 0x%x pid %u is up: %u msgs, %u units",
                  peer->nid, peer->pid, peer->msg_window, peer->unit_window);
        break;

    default:
        ucs_debug("cxi ignoring control message of unknown type %u",
                  UCT_CXI_CTRL_TYPE(mb));
        break;
    }
}


/* -------------------------------------------------------------------------
 * Handshake driver
 * -------------------------------------------------------------------------
 */

void uct_cxi_peer_connect(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer)
{
    ucs_time_t now = ucs_get_time();

    if ((peer->state != UCT_CXI_PEER_DOWN) ||
        !ucs_list_is_empty(&peer->connecting)) {
        return;
    }

    peer->deadline     = now + iface->fc.connect_timeout;
    peer->next_attempt = now;
    peer->attempts     = 0;
    ucs_list_add_tail(&iface->fc.connecting, &peer->connecting);
    uct_cxi_fc_progress(iface);
}

void uct_cxi_fc_progress(uct_cxi_iface_t *iface)
{
    ucs_time_t      now = ucs_get_time();
    uct_cxi_peer_t *peer, *tmp;
    unsigned        shift;
    ucs_time_t      delay;

    ucs_list_for_each_safe(peer, tmp, &iface->fc.connecting, connecting) {
        if (now > peer->deadline) {
            ucs_warn("cxi handshake with nid 0x%x pid %u timed out after "
                     "%u attempts", peer->nid, peer->pid, peer->attempts);
            uct_cxi_peer_connected(peer, UCT_CXI_PEER_FAILED);
            continue;
        }

        if (now < peer->next_attempt) {
            continue;
        }

        if (uct_cxi_ctrl_send(iface, peer, UCT_CXI_CTRL_CREQ,
                              UCT_CXI_CTRL_MATCH(UCT_CXI_CTRL_CREQ,
                                                 iface->fc.epoch, 0),
                              iface->fc.epoch) != UCS_OK) {
            continue; /* no slot or command queue room: next progress call */
        }

        peer->state = UCT_CXI_PEER_CREQ_SENT;
        shift       = ucs_min(peer->attempts, 10u);
        delay       = ucs_time_from_usec(
                              ucs_min((uint64_t)UCT_CXI_CTRL_RETRY_BASE_US
                                              << shift,
                                      (uint64_t)UCT_CXI_CTRL_RETRY_MAX_US));
        peer->next_attempt = now + delay;
        peer->attempts++;
    }
}

#endif /* UCT_CXI_DISABLE_FC */
