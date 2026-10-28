/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI connected-endpoint flow control: per-peer state and the handshake that
 * establishes it.
 *
 * The hardware is connectionless, so the transport keeps a software "peer"
 * per remote interface, shared by every endpoint to it. A peer is set up by
 * a handshake on the control channel (cxi_ctrl.c):
 *
 *   initiator                                 target
 *     CREQ(epoch) ------------------------->  creates its peer record
 *     <---------------- CREP(echo, windows)   grants the initiator its windows
 *
 * Each direction is independent.
 *
 * The windows are credits of two kinds: event slots, which bound the receive
 * EQ, and buffer space (UCT_CXI_FC_UNIT bytes) per message class that has a
 * ring of its own (uct_cxi_fc_class_t). A sender needs both to send. The
 * target returns credits after processing a message, as CUMULATIVE counters,
 * so a lost, duplicated or reordered grant is repaired by the next one. They
 * ride on any Active Message to that peer (piggyback), or on a GRANT message
 * once half a window is owed. A peer without a control PTE (--disable-cxi-fc
 * or UCX_CXI_FC_ENABLE=n) is LEGACY: uncredited, treated as connectionless.
 *
 * Without credits a slow target can overflow its queues and lose messages
 * silently; that is for bring-up and debugging only.
 *
 * Included only by cxi_iface.h, after uct_cxi_pte_fc_t.
 */

#ifndef UCT_CXI_FC_H
#define UCT_CXI_FC_H

#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/time/time.h>
#include <ucs/time/timer_wheel.h>

#include <libcxi/libcxi.h>
#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>


/* Messages with another version are ignored (the handshake then times out). */
#define UCT_CXI_CTRL_VERSION 2u

/* CREQ resend delay, doubling per attempt up to the cap. The timer wheel's
 * resolution is the base delay. */
#define UCT_CXI_CTRL_RETRY_BASE_US 50
#define UCT_CXI_CTRL_RETRY_MAX_US  50000

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

/*
 * Credit return piggybacked on an Active Message's match_bits (bits 0-6 are
 * the am_id and flags). It carries the low bits of the three cumulative
 * counters, in granules of 2^shift (uct_cxi_fc_pb_shift):
 *
 *   [7]      valid
 *   [21:8]   event slots processed, 14 bits
 *   [38:22]  Active Message buffer space processed, 17 bits
 *   [55:39]  tag matching buffer space processed, 17 bits
 *   [63:56]  sender's epoch, low 8 bits (rejects a stale incarnation)
 */
#define UCT_CXI_FC_PB_VALID      (1ULL << 7)
#define UCT_CXI_FC_PB_SLOT_SHIFT 8
#define UCT_CXI_FC_PB_SLOT_BITS  14
#define UCT_CXI_FC_PB_UNIT_BITS  17
#define UCT_CXI_FC_PB_UNIT_SHIFT(_cls) \
    (UCT_CXI_FC_PB_SLOT_SHIFT + UCT_CXI_FC_PB_SLOT_BITS + \
     UCT_CXI_FC_PB_UNIT_BITS * (_cls))
#define UCT_CXI_FC_PB_EPOCH_SHIFT 56
#define UCT_CXI_FC_PB_EPOCH_BITS  8
#define UCT_CXI_FC_PB_MASK(_bits) ((1ULL << (_bits)) - 1)

/* Pools whose counters travel: event slots (0), then each class's space. */
#define UCT_CXI_FC_NUM_POOLS (1 + UCT_CXI_FC_NUM_CLASSES)

/*
 * The least s such that \a window, in granules of 2^s, is below half of what
 * \a bits bits can tell apart. The receiver reconstructs the whole counter as
 * the value nearest the last one it knew, which is unambiguous since the
 * counter never leads by more than the window. A remainder below a granule
 * stays owed.
 */
static UCS_F_ALWAYS_INLINE unsigned
uct_cxi_fc_pb_shift(uint32_t window, unsigned bits)
{
    unsigned shift = 0;

    while ((((uint64_t)window + UCS_BIT(shift) - 1) >> shift) >=
           UCS_BIT(bits - 1)) {
        shift++;
    }
    return shift;
}

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


/* State of a peer's handshake. */
typedef enum {
    /* No CREQ answered yet, none in flight */
    UCT_CXI_PEER_DOWN,
    /* CREQ sent, waiting for the CREP */
    UCT_CXI_PEER_CREQ_SENT,
    /* CREP received: the peer's windows are known */
    UCT_CXI_PEER_UP,
    /* Peer has no control channel: uncredited */
    UCT_CXI_PEER_LEGACY,
    /* Handshake timed out */
    UCT_CXI_PEER_FAILED
} uct_cxi_peer_state_t;


/** Credits this interface HOLDS toward a peer: what it may still send. */
typedef struct uct_cxi_fc_tx {
    /* Receive event queue slots, all classes */
    int32_t  avail_slots;
    /* Receive buffer space of each class; may dip below zero by up to one
     * bcopy: its length is only known after it is packed */
    int32_t  avail_units[UCT_CXI_FC_NUM_CLASSES];
    /* Last cumulative grant applied */
    uint32_t ret_slots;
    uint32_t ret_units[UCT_CXI_FC_NUM_CLASSES];
    /* Net slots / units spent, cumulative */
    uint32_t used_slots;
    uint32_t used_units[UCT_CXI_FC_NUM_CLASSES];
} uct_cxi_fc_tx_t;

/** Credits this interface OWES a peer: what it has processed from it. */
typedef struct uct_cxi_fc_rx {
    /* Slots and units processed, cumulative */
    uint32_t ret_slots;
    uint32_t ret_units[UCT_CXI_FC_NUM_CLASSES];
    /* Last put on the wire (piggyback or GRANT) */
    uint32_t adv_slots;
    uint32_t adv_units[UCT_CXI_FC_NUM_CLASSES];
    /* Last confirmed delivered, by a GRANT's ACK */
    uint32_t acked_slots;
    uint32_t acked_units[UCT_CXI_FC_NUM_CLASSES];
} uct_cxi_fc_rx_t;


struct uct_cxi_ep;
struct uct_cxi_peer_conn;

/**
 * One remote interface, shared by all endpoints to it. It outlives them (the
 * remote may keep sending), so it is kept small: handshake state lives in a
 * pooled uct_cxi_peer_conn_t, and the NID and PID are derived from \a key.
 */
typedef struct uct_cxi_peer {
    /* CXI_MATCH_ID(pid_bits, pid, nid): the initiator hardware reports */
    uint32_t                 key;
    /* uct_cxi_peer_state_t */
    uint8_t                  state;
    /* Granule of this peer's piggybacked counters */
    uint8_t                  pb_shift[UCT_CXI_FC_NUM_POOLS];

    /* Learned from the peer: CREP's epoch (low 24 bits), CREQ's own epoch */
    uint32_t                 remote_epoch;
    uint32_t                 rx_epoch;

    /* What we may send to the peer, and what we owe it */
    uct_cxi_fc_tx_t          tx;
    uct_cxi_fc_rx_t          rx;

    /* Handshake in progress (state DOWN or CREQ_SENT), NULL otherwise */
    struct uct_cxi_peer_conn *conn;

    /* Link in fc.grants: a GRANT waits for control channel room */
    ucs_list_link_t          grants;

    /* Endpoints waiting for credits, descheduled from the arbiter until a
     * grant, the CREP or a refund (uct_cxi_peer_resume). Linked through
     * uct_cxi_ep_t::next_blocked. */
    struct uct_cxi_ep        *blocked;
} uct_cxi_peer_t;

/** A peer's handshake, from the first CREQ until the CREP or a verdict. */
typedef struct uct_cxi_peer_conn {
    /* Next CREQ (re)send, or the deadline */
    ucs_wtimer_t         timer;
    struct uct_cxi_iface *iface;
    uct_cxi_peer_t       *peer;
    /* Give up (FAILED) after this */
    ucs_time_t           deadline;
    unsigned             attempts;
} uct_cxi_peer_conn_t;

KHASH_MAP_INIT_INT(uct_cxi_peer_hash, uct_cxi_peer_t*)


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
 * Per-interface flow-control state.
 */
typedef struct uct_cxi_fc_iface {
    /* FC_ENABLE; off: no control PTE, all peers LEGACY */
    int                        enabled;
    /* Random, identifies this incarnation */
    uint32_t                   epoch;
    /* What we grant each peer: event slots, and buffer space of each class
     * (0: the class is not in use) */
    uint32_t                   slot_window;
    uint32_t                   unit_window[UCT_CXI_FC_NUM_CLASSES];
    /* Granule of our piggybacked counters */
    uint8_t                    pb_shift[UCT_CXI_FC_NUM_POOLS];
    /* Owe this many slots to a peer, or this many units of a class: send a
     * GRANT */
    uint32_t                   grant_slots;
    uint32_t                   grant_units[UCT_CXI_FC_NUM_CLASSES];
    ucs_time_t                 connect_timeout;
    khash_t(uct_cxi_peer_hash) peers;
    /* CREQ resends and handshake deadlines */
    ucs_twheel_t               twheel;
    /* Handshakes in progress: the wheel is only swept while there are any */
    unsigned                   num_connecting;
    /* uct_cxi_peer_conn_t */
    ucs_mpool_t                conn_pool;
    /* Peers with a GRANT to send, oldest first (uct_cxi_fc_flush_grants) */
    ucs_list_link_t            grants;

    /* Peer of the last Active Message received, to skip the hash lookup. */
    uint32_t                   rx_cache_key;
    uct_cxi_peer_t             *rx_cache_peer;
} uct_cxi_fc_iface_t;

#endif /* UCT_CXI_FC_H */
