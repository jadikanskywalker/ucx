/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI connected-endpoint flow control: per-peer state and the control channel
 * that establishes it.
 *
 * The CXI hardware is connectionless, so the transport builds a software
 * connection per remote interface (a "peer"), shared by every endpoint to it.
 * A peer is set up by a two-message handshake on a dedicated control PTE:
 *
 *   initiator                                 target
 *     CREQ(epoch) ------------------------->  creates its peer record
 *     <---------------- CREP(echo, windows)   grants the initiator its windows
 *
 * Each direction is independent: the initiator learns the windows the target
 * grants it, and nothing is needed in the other direction until that side
 * creates endpoints of its own.
 *
 * The windows are credits. A sender spends one message credit plus one byte
 * credit (per UCT_CXI_FC_UNIT bytes) for every Active Message it sends, and
 * may not send without them, so a sender can never have more outstanding
 * to a target than the target granted. The target hands credits back only
 * after it has processed a message (run its handler), which is what ties the
 * send rate to the target's processing rate. Credits go back as CUMULATIVE
 * counters, "I have processed N messages and M units from you so far": the
 * sender applies the increase over what it last saw, so a lost, duplicated or
 * reordered grant is harmless, and the next one repairs it. They ride
 * piggybacked on any Active Message to that peer, or on a pure GRANT control
 * message once half a window is owed. A peer whose target has no control PTE (built
 * with --disable-cxi-fc, or UCX_CXI_FC_ENABLE=n) is marked LEGACY and treated
 * as a plain connectionless peer.
 *
 * This header is included only by cxi_iface.h, after uct_cxi_pte_fc_t.
 */

#ifndef UCT_CXI_FC_H
#define UCT_CXI_FC_H

#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/time/time.h>

#include <libcxi/libcxi.h>
#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>


/* Largest windows the piggyback encoding below can represent unambiguously
 * (the sender reconstructs the full counter from a truncated one, which needs
 * the true value to be within half the range of the last it saw). */
#define UCT_CXI_FC_MAX_MSG_WINDOW   ((1u << 19) - 1)
#define UCT_CXI_FC_MAX_UNIT_WINDOW  ((1u << 23) - 1)

/* Control channel protocol version; a message with another version is
 * ignored (the sender then times out and treats the peer as FAILED). */
#define UCT_CXI_CTRL_VERSION  1u

/* Control requests (and so TX completions) in flight at once. They take their
 * own slice of the TX event queue, see UCT_CXI_TX_EQ_UNTRACKED. */
#define UCT_CXI_CTRL_SLOTS    16u

/* Connection retry: a CREQ with no CREP yet is resent after this long,
 * doubling per attempt up to the cap. */
#define UCT_CXI_CTRL_RETRY_BASE_US  50
#define UCT_CXI_CTRL_RETRY_MAX_US   50000

/*
 * Control message wire layout. Messages are zero-payload IDC sends to the
 * peer's control PTE; everything travels in the 128 bits of match_bits and
 * header_data, which the control PTE's wildcarded list entry delivers
 * verbatim.
 *
 *   match_bits  [63:60] type   [59:56] version
 *               [55:32] sender's own epoch, low 24 bits
 *               [31:0]  CREQ: 0    CREP: the requester's epoch, echoed
 *   header_data CREQ: the requester's epoch (32 bits)
 *               CREP: [63:32] message window, [31:0] byte window in
 *                     UCT_CXI_FC_UNIT units, i.e. what the responder grants
 *
 * The epoch is random per interface instance; echoing it lets a requester
 * discard a CREP answering a CREQ from a previous incarnation of itself.
 */
enum {
    UCT_CXI_CTRL_CREQ  = 1,
    UCT_CXI_CTRL_CREP  = 2,
    UCT_CXI_CTRL_GRANT = 3   /**< header_data: [63:32] messages processed,
                                  [31:0] units processed -- cumulative */
};

/*
 * Credit return piggybacked on an Active Message's match_bits. The AM list
 * entry wildcards every match bit and the transport itself uses only bits
 * 0-6 (am_id, header flag, announce flag), so bits 7-63 arrive verbatim.
 *
 *   [7]      valid
 *   [8]      reserved (credit class; only Active Messages so far)
 *   [28:9]   messages processed, cumulative, low 20 bits
 *   [52:29]  units processed, cumulative, low 24 bits
 *   [60:53]  sender's epoch, low 8 bits (rejects a stale incarnation)
 */
#define UCT_CXI_FC_PB_VALID        (1ULL << 7)
#define UCT_CXI_FC_PB_MSG_SHIFT    9
#define UCT_CXI_FC_PB_MSG_BITS     20
#define UCT_CXI_FC_PB_UNIT_SHIFT   29
#define UCT_CXI_FC_PB_UNIT_BITS    24
#define UCT_CXI_FC_PB_EPOCH_SHIFT  53
#define UCT_CXI_FC_PB_EPOCH_BITS   8
#define UCT_CXI_FC_PB_MASK(_bits)  ((1ULL << (_bits)) - 1)

#define UCT_CXI_CTRL_TYPE(_mb)       ((unsigned)((_mb) >> 60))
#define UCT_CXI_CTRL_VER(_mb)        ((unsigned)(((_mb) >> 56) & 0xf))
#define UCT_CXI_CTRL_EPOCH24(_mb)    ((uint32_t)(((_mb) >> 32) & 0xffffff))
#define UCT_CXI_CTRL_ECHO(_mb)       ((uint32_t)((_mb) & 0xffffffffu))
#define UCT_CXI_CTRL_MATCH(_type, _epoch24, _echo) \
    (((uint64_t)(_type) << 60) | ((uint64_t)UCT_CXI_CTRL_VERSION << 56) | \
     ((uint64_t)((_epoch24) & 0xffffff) << 32) | (uint64_t)(_echo))


/* tx_state of a peer. */
typedef enum {
    UCT_CXI_PEER_DOWN,       /**< no CREQ answered yet, none in flight */
    UCT_CXI_PEER_CREQ_SENT,  /**< CREQ sent, waiting for the CREP */
    UCT_CXI_PEER_UP,         /**< CREP received: the peer's windows are known */
    UCT_CXI_PEER_LEGACY,     /**< peer has no control channel: uncredited */
    UCT_CXI_PEER_FAILED      /**< handshake timed out */
} uct_cxi_peer_state_t;


/** Credits this interface HOLDS toward a peer: what it may still send. */
typedef struct uct_cxi_fc_tx {
    int32_t   avail_msgs;
    int32_t   avail_units;  /**< may dip below zero by up to one bcopy: its
                                 length is only known after it is packed */
    uint32_t  ret_msgs;     /**< last cumulative grant applied */
    uint32_t  ret_units;
    uint32_t  used_msgs;    /**< net messages / units spent, cumulative */
    uint32_t  used_units;
} uct_cxi_fc_tx_t;

/** Credits this interface OWES a peer: what it has processed from it. */
typedef struct uct_cxi_fc_rx {
    uint32_t  ret_msgs;     /**< messages processed, cumulative */
    uint32_t  ret_units;
    uint32_t  adv_msgs;     /**< last put on the wire (piggyback or GRANT) */
    uint32_t  adv_units;
    uint32_t  acked_msgs;   /**< last confirmed delivered, by a GRANT's ACK */
    uint32_t  acked_units;
} uct_cxi_fc_rx_t;

struct uct_cxi_ep;

/**
 * One remote interface. Shared by all endpoints to it and kept for the life
 * of the local interface: the remote may keep sending after our last endpoint
 * to it is gone, so its record must outlive them (the same reasoning as
 * tag.rndv_peer_cache). Memory is proportional to the number of distinct
 * remote interfaces ever contacted, not to endpoints.
 */
typedef struct uct_cxi_peer {
    uint32_t          key;          /**< CXI_MATCH_ID(pid_bits, pid, nid) --
                                         the value hardware reports as an
                                         event's initiator */
    uint32_t          nid;
    uint32_t          pid;
    uint8_t           state;        /**< uct_cxi_peer_state_t */
    union c_fab_addr  dfa_ctrl;     /**< the peer's control PTE */
    uint8_t           dfa_ctrl_idx_ext;

    /* Handshake in progress (state DOWN or CREQ_SENT) */
    ucs_list_link_t   connecting;   /**< link in fc.connecting */
    ucs_time_t        next_attempt; /**< when to (re)send the CREQ */
    ucs_time_t        deadline;     /**< give up (FAILED) after this */
    unsigned          attempts;

    /* Learned from the peer */
    uint32_t          remote_epoch; /**< CREP: the peer's epoch, low 24 bits */
    uint32_t          msg_window;   /**< CREP: message credits granted to us */
    uint32_t          unit_window;  /**< CREP: byte credits granted, in units */
    uint32_t          rx_epoch;     /**< CREQ: the peer's own epoch */

    uct_cxi_fc_tx_t   tx;           /**< what we may send to the peer */
    uct_cxi_fc_rx_t   rx;           /**< what we owe the peer */

    /* Pure GRANT waiting to be sent (no ctrl slot or command queue room) */
    ucs_list_link_t   grants;       /**< link in fc.grants */

    /* Endpoints to this peer whose pending queue is waiting for credits,
     * descheduled from the arbiter until a grant, the CREP or a refund
     * makes them runnable again (see uct_cxi_peer_resume). Singly linked
     * through uct_cxi_ep_t::next_blocked, so an ep costs one pointer. */
    struct uct_cxi_ep *blocked;
} uct_cxi_peer_t;

KHASH_MAP_INIT_INT(uct_cxi_peer_hash, uct_cxi_peer_t*)


/**
 * A control message in flight. Fire-and-forget: the only thing the
 * completion looks at is a PTLTE_NOT_FOUND on a CREQ, which means the peer
 * has no control channel. Everything else (a dropped CREQ, a dropped CREP) is
 * repaired by the CREQ being resent until a CREP arrives.
 */
typedef struct uct_cxi_ctrl_req {
    uct_cxi_peer_t   *peer;
    unsigned          type;         /**< UCT_CXI_CTRL_CREQ, _CREP or _GRANT */
    uint32_t          grant_msgs;   /**< GRANT: the cumulative values sent, */
    uint32_t          grant_units;  /**<   to record as delivered on its ACK */
} uct_cxi_ctrl_req_t;


/**
 * Per-interface flow-control state.
 */
typedef struct uct_cxi_fc_iface {
    int               enabled;      /**< FC_ENABLE: off => every peer LEGACY and
                                         no control PTE is opened */
    uint32_t          epoch;        /**< random, identifies this incarnation */
    uint32_t          msg_window;   /**< what we grant each peer */
    uint32_t          unit_window;
    uint32_t          grant_msgs;   /**< owe this many messages to a peer, or */
    uint32_t          grant_units;  /**<   this many units: send a GRANT */
    ucs_time_t        connect_timeout;
    khash_t(uct_cxi_peer_hash) peers;
    ucs_list_link_t   connecting;   /**< peers with a handshake in progress */
    ucs_list_link_t   grants;       /**< peers with a GRANT still to send */

    /* One-entry cache for the receive path: the peer the last Active Message
     * came from, to spare a hash lookup per message. */
    uint32_t          rx_cache_key;
    uct_cxi_peer_t   *rx_cache_peer;
    ucs_mpool_t       ctrl_req_pool; /**< uct_cxi_ctrl_req_t, UCT_CXI_CTRL_SLOTS */

    /* Control PTE: matching, one persistent zero-length list entry that
     * accepts every message, so control traffic consumes no buffer and can
     * only be refused when the receive event queue is full. */
    struct {
        struct cxil_pte      *pte;
        struct cxil_pte_map  *pte_map;
        uint16_t              ptn;   /**< cached for the event dispatch */
        uct_cxi_pte_fc_t      fc;
    } ctrl;
} uct_cxi_fc_iface_t;

#endif /* UCT_CXI_FC_H */
