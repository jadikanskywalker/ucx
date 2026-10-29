/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI control channel (cxi_ctrl.c): its types, the layout of the messages
 * it carries and its interface. Included only by cxi_iface.h, after cxi_eq.h
 * and cxi_fc.h.
 */

#ifndef UCT_CXI_CTRL_H
#define UCT_CXI_CTRL_H

#include <ucs/sys/compiler_def.h>


/* Control channel: messages in flight, command queue depth (two commands per
 * message) and default EQ depth. */
#define UCT_CXI_CTRL_MAX_INFLIGHT  64U
#define UCT_CXI_CTRL_CMDQ_DEPTH    256U
#define UCT_CXI_CTRL_EQ_NUM_EVENTS 256U

/* Messages with another version are ignored (the handshake then times out). */
#define UCT_CXI_CTRL_VERSION 2u

/*
 * Control message layout, in the match_bits and header_data of a zero-payload
 * send:
 *
 *   match_bits  [63:60] type   [59:56] version
 *               [55:32] sender's own epoch, low 24 bits
 *               [31:0]  CREQ: 0    CREP: the requester's epoch, echoed
 *                       GRANT: tag matching buffer space processed
 *   header_data CREQ: the requester's epoch (32 bits)
 *               CREP: what the responder grants: [63:40] event slots,
 *                     [39:20] Active Message buffer space, [19:0] tag
 *                     matching buffer space, the latter two in multiples of
 *                     UCT_CXI_FC_WINDOW_GRAIN units
 *               GRANT: [63:32] event slots processed, [31:0] Active Message
 *                     buffer space processed (the whole counters)
 *
 * The epoch is random per interface instance; the echo lets a requester
 * discard a CREP meant for a previous incarnation of itself.
 */
enum {
    UCT_CXI_CTRL_CREQ  = 1,
    UCT_CXI_CTRL_CREP  = 2,
    /* Cumulative credits processed so far */
    UCT_CXI_CTRL_GRANT = 3
};

/* The CREP's grant, in header_data (see the layout above). */
#define UCT_CXI_CREP_PACK(_slots, _am_units, _tag_units) \
    (((uint64_t)(_slots) << 40) | \
     ((uint64_t)((_am_units) / UCT_CXI_FC_WINDOW_GRAIN) << 20) | \
     (uint64_t)((_tag_units) / UCT_CXI_FC_WINDOW_GRAIN))
#define UCT_CXI_CREP_SLOTS(_hd) ((uint32_t)((_hd) >> 40))
#define UCT_CXI_CREP_UNITS(_hd, _cls) \
    ((uint32_t)((((_hd) >> ((_cls) == UCT_CXI_FC_AM ? 20 : 0)) & \
                 UCT_CXI_FC_PB_MASK(20)) * \
                UCT_CXI_FC_WINDOW_GRAIN))

#define UCT_CXI_CTRL_TYPE(_mb)    ((unsigned)((_mb) >> 60))
#define UCT_CXI_CTRL_VER(_mb)     ((unsigned)(((_mb) >> 56) & 0xf))
#define UCT_CXI_CTRL_EPOCH24(_mb) ((uint32_t)(((_mb) >> 32) & 0xffffff))
#define UCT_CXI_CTRL_ECHO(_mb)    ((uint32_t)((_mb)&0xffffffffu))
#define UCT_CXI_CTRL_MATCH(_type, _epoch24, _echo) \
    (((uint64_t)(_type) << 60) | ((uint64_t)UCT_CXI_CTRL_VERSION << 56) | \
     ((uint64_t)((_epoch24)&0xffffff) << 32) | (uint64_t)(_echo))

/**
 * A control message in flight. Fire-and-forget: its completion only matters
 * for PTLTE_NOT_FOUND on a CREQ (peer has no control channel) and for a GRANT.
 */
typedef struct uct_cxi_ctrl_req {
    uct_cxi_peer_t *peer;
    /* UCT_CXI_CTRL_CREQ, _CREP or _GRANT */
    unsigned       type;
    /* GRANT: cumulative values sent, recorded as delivered on its ACK */
    uint32_t       grant_slots;
    uint32_t       grant_units[UCT_CXI_FC_NUM_CLASSES];
} uct_cxi_ctrl_req_t;

/**
 * The control channel (cxi_ctrl.c): its own PTE, event queue and command queue.
 */
typedef struct uct_cxi_ctrl {
    /* Opened (FC_ENABLE) */
    int                 enabled;
    uct_cxi_eq_t        eq;
    struct cxi_cq       *cmdq;
    struct cxil_pte     *pte;
    struct cxil_pte_map *pte_map;
    /* uct_cxi_ctrl_req_t */
    ucs_mpool_t         req_pool;
    unsigned            outstanding;
    /* One reserved EQ slot per message */
    unsigned            max_inflight;
} uct_cxi_ctrl_t;

BEGIN_C_DECLS

ucs_status_t uct_cxi_ctrl_open(uct_cxi_iface_t *iface,
                               const uct_cxi_iface_config_t *config,
                               struct cxil_lni *lni);
void uct_cxi_ctrl_close(uct_cxi_iface_t *iface);

/**
 * Send a control message to \a peer; UCS_ERR_NO_RESOURCE if the channel is
 * full. \a grant_slots and \a grant_units are what a GRANT carries.
 */
ucs_status_t uct_cxi_ctrl_send(uct_cxi_iface_t *iface, uct_cxi_peer_t *peer,
                               unsigned type, uint64_t match_bits,
                               uint64_t header_data, uint32_t grant_slots,
                               const uint32_t *grant_units);

END_C_DECLS

#endif /* UCT_CXI_CTRL_H */
