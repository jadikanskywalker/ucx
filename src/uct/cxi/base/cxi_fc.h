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
 * The windows are credits, of two kinds. Event slots bound the receive event
 * queue, which everything a peer sends shares: a message costs the slots of
 * the events it can leave in the queue until it has been processed. Buffer
 * space (in units of UCT_CXI_FC_UNIT bytes) bounds a receive ring, and each
 * class of message that has a ring of its own (Active Messages, tag matching;
 * see uct_cxi_fc_class_t) has a pool of its own. A sender may not send
 * without credits of both kinds, so it can never have more outstanding to a
 * target than the target granted. The target hands credits back only after it
 * has processed a message (run its handler), which is what ties the send rate
 * to the target's processing rate. Credits go back as CUMULATIVE counters, "I
 * have processed N slots and M units from you so far": the sender applies the
 * increase over what it last saw, so a lost, duplicated or reordered grant is
 * harmless, and the next one repairs it. They ride piggybacked on any Active
 * Message to that peer, or on a pure GRANT control message once half a window
 * is owed. A peer whose target has no control PTE (built with
 * --disable-cxi-fc, or UCX_CXI_FC_ENABLE=n) is marked LEGACY and treated as a
 * plain connectionless peer.
 *
 * Without credits nothing ties a sender to its target's processing rate, and
 * the transport cannot make up for it. A target that falls behind (a stream of
 * small tagged messages, whose each costs it an arrival, a search, a callback
 * and a receive to post) fills its receive event queue or its unexpected
 * list; the hardware then disables its portal table entry (flow control, with
 * the reason EQ full or unexpected-list failure), recovery enables it again,
 * and the messages sent in between are lost without the sender being told:
 * UCP tag_bw at 8 B, with flow control off, stops after about a thousand
 * messages in some runs (a larger UCX_CXI_EQ_SIZE only moves where). A
 * build or run without flow control is for bring-up and debugging, with
 * traffic the target keeps up with.
 *
 * This header is included only by cxi_iface.h, after uct_cxi_pte_fc_t.
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


/* Control channel protocol version; a message with another version is
 * ignored (the sender then times out and treats the peer as FAILED). */
#define UCT_CXI_CTRL_VERSION  2u

/* Connection retry: a CREQ with no CREP yet is resent after this long,
 * doubling per attempt up to the cap. A GRANT that could not be sent, or was
 * lost, is retried on the same schedule, doubling with each consecutive loss.
 * The retries are timers of a timer wheel (uct_cxi_fc_iface_t::twheel) whose
 * resolution is this base delay, so every delay is at least one slot. */
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
 *                       GRANT: tag matching buffer space processed
 *   header_data CREQ: the requester's epoch (32 bits)
 *               CREP: what the responder grants: [63:40] event slots,
 *                     [39:20] Active Message buffer space, [19:0] tag
 *                     matching buffer space, the latter two in multiples of
 *                     UCT_CXI_FC_WINDOW_GRAIN units
 *               GRANT: [63:32] event slots processed, [31:0] Active Message
 *                     buffer space processed (the whole counters, see below)
 *
 * The epoch is random per interface instance; echoing it lets a requester
 * discard a CREP answering a CREQ from a previous incarnation of itself.
 */
enum {
    UCT_CXI_CTRL_CREQ  = 1,
    UCT_CXI_CTRL_CREP  = 2,
    UCT_CXI_CTRL_GRANT = 3   /**< the credits processed so far, cumulative:
                                  see the layout above */
};

/*
 * Credit return piggybacked on an Active Message's match_bits. The AM list
 * entry wildcards every match bit and the transport itself uses only bits
 * 0-6 (am_id, header flag, announce flag), so bits 7-63 arrive verbatim. A
 * piggyback carries all three cumulative counters (event slots, and the buffer
 * space of each class), each cut down to the low bits of the counter in
 * granules of 2^shift (see uct_cxi_fc_pb_shift):
 *
 *   [7]      valid
 *   [21:8]   event slots processed, 14 bits
 *   [38:22]  Active Message buffer space processed, 17 bits
 *   [55:39]  tag matching buffer space processed, 17 bits
 *   [63:56]  sender's epoch, low 8 bits (rejects a stale incarnation)
 *
 * A pure GRANT carries the whole counters.
 */
#define UCT_CXI_FC_PB_VALID        (1ULL << 7)
#define UCT_CXI_FC_PB_SLOT_SHIFT   8
#define UCT_CXI_FC_PB_SLOT_BITS    14
#define UCT_CXI_FC_PB_UNIT_BITS    17
#define UCT_CXI_FC_PB_UNIT_SHIFT(_cls) \
    (UCT_CXI_FC_PB_SLOT_SHIFT + UCT_CXI_FC_PB_SLOT_BITS + \
     UCT_CXI_FC_PB_UNIT_BITS * (_cls))
#define UCT_CXI_FC_PB_EPOCH_SHIFT  56
#define UCT_CXI_FC_PB_EPOCH_BITS   8
#define UCT_CXI_FC_PB_MASK(_bits)  ((1ULL << (_bits)) - 1)

/* Pools whose counters travel: event slots (0), then each class's space. */
#define UCT_CXI_FC_NUM_POOLS       (1 + UCT_CXI_FC_NUM_CLASSES)

/*
 * The least s such that a window of \a window, in granules of 2^s, is below
 * half of what \a bits bits can tell apart. A counter on the wire is the low
 * \a bits bits of the real one in such granules, and the receiver of it works
 * out the whole by taking the nearest value to the last it knew; what it is
 * ahead by is never more than the window, so that is unambiguous. Both sides
 * know the window (it is what the CREP granted), hence the shift, and no
 * window is too large: a large one is just counted more coarsely. The
 * remainder less than a granule stays owed until more has been processed.
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
#define UCT_CXI_CREP_SLOTS(_hd)      ((uint32_t)((_hd) >> 40))
#define UCT_CXI_CREP_UNITS(_hd, _cls) \
    ((uint32_t)((((_hd) >> ((_cls) == UCT_CXI_FC_AM ? 20 : 0)) & \
                 UCT_CXI_FC_PB_MASK(20)) * UCT_CXI_FC_WINDOW_GRAIN))

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
    int32_t   avail_slots;  /**< receive event queue slots, all classes */
    int32_t   avail_units[UCT_CXI_FC_NUM_CLASSES];
                            /**< receive buffer space of each class; may dip
                                 below zero by up to one bcopy: its length is
                                 only known after it is packed */
    uint32_t  ret_slots;    /**< last cumulative grant applied */
    uint32_t  ret_units[UCT_CXI_FC_NUM_CLASSES];
    uint32_t  used_slots;   /**< net slots / units spent, cumulative */
    uint32_t  used_units[UCT_CXI_FC_NUM_CLASSES];
} uct_cxi_fc_tx_t;

/** Credits this interface OWES a peer: what it has processed from it. */
typedef struct uct_cxi_fc_rx {
    uint32_t  ret_slots;    /**< slots processed, cumulative */
    uint32_t  ret_units[UCT_CXI_FC_NUM_CLASSES];
    uint32_t  adv_slots;    /**< last put on the wire (piggyback or GRANT) */
    uint32_t  adv_units[UCT_CXI_FC_NUM_CLASSES];
    uint32_t  acked_slots;  /**< last confirmed delivered, by a GRANT's ACK */
    uint32_t  acked_units[UCT_CXI_FC_NUM_CLASSES];
} uct_cxi_fc_rx_t;


struct uct_cxi_ep;
struct uct_cxi_peer_conn;

/**
 * One remote interface. Shared by all endpoints to it and kept for the life
 * of the local interface: the remote may keep sending after our last endpoint
 * to it is gone, so its record must outlive them (the same reasoning as
 * tag.rndv_peer_cache). So its size is a cost of every connection, and holds
 * only what is needed for as long as the peer is used: what the handshake
 * needs lives in a uct_cxi_peer_conn_t, taken from a pool for as long as the
 * handshake lasts, and the peer's NID and PID, and where its control PTE is,
 * are worked out from \a key when a control message is sent.
 */
typedef struct uct_cxi_peer {
    uint32_t          key;          /**< CXI_MATCH_ID(pid_bits, pid, nid) --
                                         the value hardware reports as an
                                         event's initiator */
    uint8_t           state;        /**< uct_cxi_peer_state_t */
    uint8_t           pb_shift[UCT_CXI_FC_NUM_POOLS];
                                    /**< granule of the counters this peer's
                                         piggybacks carry (uct_cxi_fc_pb_shift
                                         of the windows it granted us) */

    /* Learned from the peer */
    uint32_t          remote_epoch; /**< CREP: the peer's epoch, low 24 bits */
    uint32_t          rx_epoch;     /**< CREQ: the peer's own epoch */

    uct_cxi_fc_tx_t   tx;           /**< what we may send to the peer */
    uct_cxi_fc_rx_t   rx;           /**< what we owe the peer */

    /* Handshake in progress (state DOWN or CREQ_SENT), NULL otherwise */
    struct uct_cxi_peer_conn *conn;

    /* Pure GRANT waiting to be sent (no ctrl slot or command queue room) */
    ucs_list_link_t   grants;       /**< link in fc.grants */

    /* Endpoints to this peer whose pending queue is waiting for credits,
     * descheduled from the arbiter until a grant, the CREP or a refund
     * makes them runnable again (see uct_cxi_peer_resume). Singly linked
     * through uct_cxi_ep_t::next_blocked, so an ep costs one pointer. */
    struct uct_cxi_ep *blocked;
} uct_cxi_peer_t;

/**
 * A peer's handshake while it lasts: from the first CREQ until the CREP (or
 * a verdict of LEGACY or FAILED). The CREQ is resent on a timer until
 * answered.
 */
typedef struct uct_cxi_peer_conn {
    ucs_wtimer_t      timer;        /**< next CREQ (re)send, or the deadline */
    struct uct_cxi_iface *iface;
    uct_cxi_peer_t   *peer;
    ucs_time_t        deadline;     /**< give up (FAILED) after this */
    unsigned          attempts;
} uct_cxi_peer_conn_t;

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
    uint32_t          grant_slots;  /**< GRANT: the cumulative values sent, */
    uint32_t          grant_units[UCT_CXI_FC_NUM_CLASSES];
                                    /**<   to record as delivered on its ACK */
} uct_cxi_ctrl_req_t;


/**
 * Per-interface flow-control state.
 */
typedef struct uct_cxi_fc_iface {
    int               enabled;      /**< FC_ENABLE: off => every peer LEGACY and
                                         no control PTE is opened */
    uint32_t          epoch;        /**< random, identifies this incarnation */
    uint32_t          slot_window;  /**< what we grant each peer: event slots, */
    uint32_t          unit_window[UCT_CXI_FC_NUM_CLASSES];
                                    /**<   and buffer space of each class (0:
                                         the class is not in use) */
    uint8_t           pb_shift[UCT_CXI_FC_NUM_POOLS];
                                    /**< granule of the counters our piggybacks
                                         carry: of our own windows */
    uint32_t          grant_slots;  /**< owe this many slots to a peer, or */
    uint32_t          grant_units[UCT_CXI_FC_NUM_CLASSES];
                                    /**<   this many units of a class: send a
                                         GRANT */
    ucs_time_t        connect_timeout;
    khash_t(uct_cxi_peer_hash) peers;
    ucs_twheel_t      twheel;       /**< CREQ resends and handshake deadlines */
    unsigned          num_connecting; /**< handshakes in progress: the wheel is
                                         only swept while there are any */
    ucs_mpool_t       conn_pool;    /**< uct_cxi_peer_conn_t */
    ucs_list_link_t   grants;       /**< peers with a GRANT still to send, in
                                         the order they were found to need
                                         one. Retried when TX completions free
                                         room, and on grant_timer. */
    ucs_wtimer_t      grant_timer;  /**< retries the grants while any wait */
    unsigned          grant_failures; /**< GRANTs lost in a row: the backoff of
                                           grant_timer */

    /* One-entry cache for the receive path: the peer the last Active Message
     * came from, to spare a hash lookup per message. */
    uint32_t          rx_cache_key;
    uct_cxi_peer_t   *rx_cache_peer;
    ucs_mpool_t       ctrl_req_pool; /**< uct_cxi_ctrl_req_t: a control message
                                          is counted in iface->tx.outstanding
                                          like any send, so there are never
                                          more than max_inflight of them */

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
