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
 * creates endpoints of its own. A peer whose target has no control PTE (built
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


/* Flow-control credit unit: byte windows are counted in these. */
#define UCT_CXI_FC_UNIT       64u

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
    UCT_CXI_CTRL_CREQ = 1,
    UCT_CXI_CTRL_CREP = 2
};

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
    unsigned          type;         /**< UCT_CXI_CTRL_CREQ or _CREP */
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
    ucs_time_t        connect_timeout;
    khash_t(uct_cxi_peer_hash) peers;
    ucs_list_link_t   connecting;   /**< peers with a handshake in progress */
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
