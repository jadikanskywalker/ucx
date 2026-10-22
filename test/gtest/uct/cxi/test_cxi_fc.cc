/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI connected-endpoint flow control: peer records and the handshake on the
 * control channel.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifndef UCT_CXI_DISABLE_FC

#include "test_cxi_rma.h"

#include <uct/cxi/base/cxi_ep.h>
#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <functional>
#include <string>
#include <vector>
#include <unistd.h>


/**
 * Two entities on the same node, each with its own iface and so its own
 * network identity: a handshake between them runs over the real control PTE.
 */
class test_cxi_fc : public test_cxi_rma_base {
public:
    uct_cxi_iface_t *cxi_iface(entity &ent)
    {
        return ucs_derived_of(ent.iface(), uct_cxi_iface_t);
    }

    uct_cxi_peer_t *peer_of(entity &ent, unsigned ep_idx)
    {
        return ucs_derived_of(ent.ep(ep_idx), uct_cxi_ep_t)->peer;
    }

    /** The record @a ent's iface holds for remote iface @a remote, or NULL. */
    uct_cxi_peer_t *find_peer(entity &ent, entity &remote)
    {
        uct_cxi_iface_t *iface  = cxi_iface(ent);
        uct_cxi_iface_t *riface = cxi_iface(remote);
        uct_cxi_md_t    *md     = uct_cxi_iface_md(iface);
        uint32_t         key    = CXI_MATCH_ID(md->pid_bits,
                                               riface->domain->pid,
                                               uct_cxi_iface_md(riface)->
                                                       device.nid);
        khiter_t         iter   = kh_get(uct_cxi_peer_hash, &iface->fc.peers,
                                         key);

        return (iter == kh_end(&iface->fc.peers)) ?
               NULL : kh_value(&iface->fc.peers, iter);
    }

    /** Progress both ifaces until @a done, for at most @a timeout_sec. */
    bool progress_until(const std::function<bool()> &done,
                        double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);

        while (!done() && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        return done();
    }
};


/**
 * Creating an endpoint handshakes with the remote iface: the initiator ends
 * up with the windows the target grants it, and the target has a record of the
 * initiator. The record is found by the identity the initiator computed from
 * the target's address, but was created from the initiator field of the CREQ
 * event, so this also checks the two agree.
 */
UCS_TEST_P(test_cxi_fc, handshake_basic)
{
    sender().connect_to_iface(0, receiver());
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_NE(nullptr, peer);

    ASSERT_TRUE(progress_until([&]() {
        return peer->state == UCT_CXI_PEER_UP;
    })) << "handshake did not complete, peer state " << (int)peer->state;

    /* Nothing has been spent yet: what the target granted is what is left. */
    uct_cxi_iface_t *riface = cxi_iface(receiver());
    EXPECT_EQ(riface->fc.slot_window, (uint32_t)peer->tx.avail_slots);
    EXPECT_EQ(riface->fc.unit_window[UCT_CXI_FC_AM],
              (uint32_t)peer->tx.avail_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(riface->fc.unit_window[UCT_CXI_FC_TAG],
              (uint32_t)peer->tx.avail_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(riface->fc.epoch & 0xffffff, peer->remote_epoch);
    for (unsigned i = 0; i < UCT_CXI_FC_NUM_POOLS; i++) {
        EXPECT_EQ(riface->fc.pb_shift[i], peer->pb_shift[i])
                << "the two sides disagree on the granule of counter " << i;
    }

    /* The target knows the initiator, but has started nothing of its own. */
    uct_cxi_peer_t *back = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, back) << "target never recorded the initiator";
    EXPECT_EQ(cxi_iface(sender())->fc.epoch, back->rx_epoch);
    EXPECT_EQ(UCT_CXI_PEER_DOWN, back->state);
    EXPECT_EQ(nullptr, back->conn);
    EXPECT_EQ(nullptr, peer->conn) << "the handshake's record outlived it";
    EXPECT_EQ(0u, cxi_iface(sender())->fc.num_connecting);
}

/**
 * Each direction is its own handshake: endpoints created both ways at once
 * both complete.
 */
UCS_TEST_P(test_cxi_fc, handshake_both_directions)
{
    sender().connect_to_iface(0, receiver());
    receiver().connect_to_iface(0, sender());
    uct_cxi_peer_t *fwd = peer_of(sender(), 0);
    uct_cxi_peer_t *rev = peer_of(receiver(), 0);
    ASSERT_NE(nullptr, fwd);
    ASSERT_NE(nullptr, rev);

    ASSERT_TRUE(progress_until([&]() {
        return (fwd->state == UCT_CXI_PEER_UP) &&
               (rev->state == UCT_CXI_PEER_UP);
    })) << "states " << (int)fwd->state << " / " << (int)rev->state;

    /* The initiator's own record of the target and the target's record of the
     * initiator are one and the same object for each side. */
    EXPECT_EQ(fwd, find_peer(sender(), receiver()));
    EXPECT_EQ(rev, find_peer(receiver(), sender()));
}

/**
 * Endpoints to the same remote iface share one peer and one handshake.
 */
UCS_TEST_P(test_cxi_fc, one_peer_per_remote_iface)
{
    sender().connect_to_iface(0, receiver());
    sender().connect_to_iface(1, receiver());
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_NE(nullptr, peer);

    EXPECT_EQ(peer, peer_of(sender(), 1));
    EXPECT_EQ(1u, kh_size(&cxi_iface(sender())->fc.peers));
    ASSERT_TRUE(progress_until([&]() {
        return peer->state == UCT_CXI_PEER_UP;
    }));
}


/**
 * A target without the control channel is a legacy peer: the CREQ is refused
 * (no such PTE) and the initiator stops asking and carries on without flow
 * control. Here the target just has UCX_CXI_FC_ENABLE=n.
 */
class test_cxi_fc_legacy : public test_cxi_fc {
protected:
    void init() override
    {
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(0)); /* sender: FC on */
        modify_config("CXI_FC_ENABLE", "n");
        m_entities.push_back(uct_test::create_entity(0)); /* receiver: off */
    }
};

UCS_TEST_P(test_cxi_fc_legacy, peer_without_control_channel)
{
    ASSERT_NE(nullptr, cxi_iface(sender()));
    ASSERT_EQ(nullptr, cxi_iface(receiver())->fc.ctrl.pte)
            << "FC_ENABLE=n must not open the control PTE";

    sender().connect_to_iface(0, receiver());
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_NE(nullptr, peer);

    ASSERT_TRUE(progress_until([&]() {
        return peer->state == UCT_CXI_PEER_LEGACY;
    })) << "peer state " << (int)peer->state << ", expected LEGACY ("
        << UCT_CXI_PEER_LEGACY << ")";
    EXPECT_EQ(nullptr, peer->conn);
    EXPECT_EQ(0u, cxi_iface(sender())->fc.num_connecting);
}

/**
 * A CREQ that is not answered is sent again, on a timer, until it is. The
 * target takes the CREQ but is not progressed, so it answers nothing: the
 * initiator keeps resending (more than once in a few milliseconds, as the
 * delay starts at 50 microseconds and doubles) and has a record of the
 * handshake until the answer arrives, which then goes away with it.
 */
UCS_TEST_P(test_cxi_fc, handshake_resends_until_answered)
{
    sender().connect_to_iface(0, receiver());
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_NE(nullptr, peer);

    /* Only the initiator is progressed. */
    ucs_time_t until = ucs_get_time() + ucs_time_from_msec(20);
    while (ucs_get_time() < until) {
        uct_iface_progress(sender().iface());
    }
    ASSERT_NE(nullptr, peer->conn) << "the handshake ended without an answer";
    EXPECT_EQ(UCT_CXI_PEER_CREQ_SENT, peer->state);
    EXPECT_GE(peer->conn->attempts, 3u) << "the CREQ was not resent";
    EXPECT_EQ(1u, cxi_iface(sender())->fc.num_connecting);

    /* Now the target answers (the first of the CREQs it has waiting). */
    ASSERT_TRUE(progress_until([&]() {
        return peer->state == UCT_CXI_PEER_UP;
    })) << "no handshake after the target was progressed, state "
        << (int)peer->state;
    EXPECT_EQ(nullptr, peer->conn);
    EXPECT_EQ(0u, cxi_iface(sender())->fc.num_connecting);
}

/**
 * A handshake that is never answered is given up on at its deadline: the peer
 * is FAILED, sends to it fail instead of waiting, and its record is gone.
 */
class test_cxi_fc_timeout : public test_cxi_fc {
public:
    void init() override
    {
        modify_config("CXI_FC_CONNECT_TIMEOUT", "0.2");
        test_cxi_rma_base::init();
    }
};

UCS_TEST_P(test_cxi_fc_timeout, unanswered_handshake_fails)
{
    sender().connect_to_iface(0, receiver());
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_NE(nullptr, peer);

    /* The target is never progressed. Giving up is reported with a warning. */
    {
        scoped_log_handler wrap_warn(wrap_warns_logger);
        ucs_time_t         until = ucs_get_time() + ucs_time_from_sec(1.0);

        while ((peer->state != UCT_CXI_PEER_FAILED) &&
               (ucs_get_time() < until)) {
            uct_iface_progress(sender().iface());
        }
    }

    EXPECT_EQ(UCT_CXI_PEER_FAILED, peer->state);
    EXPECT_EQ(nullptr, peer->conn);
    EXPECT_EQ(0u, cxi_iface(sender())->fc.num_connecting);

    uint64_t payload = 0;
    EXPECT_EQ(UCS_ERR_ENDPOINT_TIMEOUT,
              uct_ep_am_short(sender().ep(0), 1, 0, &payload,
                              sizeof(payload)));
}

/**
 * With flow control off, no peer records are kept and no handshake runs.
 */
class test_cxi_fc_off : public test_cxi_rma_base {
protected:
    void init() override
    {
        modify_config("CXI_FC_ENABLE", "n");
        test_cxi_rma_base::init();
    }
};

UCS_TEST_P(test_cxi_fc_off, no_peers_when_disabled)
{
    sender().connect_to_iface(0, receiver());
    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);

    EXPECT_EQ(nullptr, ucs_derived_of(sender().ep(0), uct_cxi_ep_t)->peer);
    EXPECT_EQ(nullptr, siface->fc.ctrl.pte);
    EXPECT_EQ(0u, kh_size(&siface->fc.peers));
}


/* ------------------------------------------------------------------------
 * Credits
 * ------------------------------------------------------------------------
 */

static ucs_status_t count_am_handler(void *arg, void *data, size_t length,
                                     unsigned flags)
{
    ++*static_cast<unsigned*>(arg);
    return UCS_OK;
}

/**
 * Active Message credits. A small message window (8) means a handful of sends
 * exhaust it; the grant threshold is then half a window (4 messages).
 */
class test_cxi_fc_credits : public test_cxi_fc {
public:
    static const uint8_t  AM_ID      = 1;
    static const unsigned MSG_WINDOW = 8;

    void init() override
    {
        modify_config("CXI_FC_MSG_WINDOW", std::to_string(MSG_WINDOW));
        m_received = 0;
        test_cxi_rma_base::init();
    }

    /** Count the Active Messages that reach the receiver's handler. */
    void count_receives()
    {
        ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), AM_ID,
                                               count_am_handler, &m_received,
                                               0));
    }

    ucs_status_t send_short(uct_ep_h ep)
    {
        uint64_t payload = 0;
        return uct_ep_am_short(ep, AM_ID, 0, &payload, sizeof(payload));
    }

    unsigned m_received;
};

const uint8_t  test_cxi_fc_credits::AM_ID;
const unsigned test_cxi_fc_credits::MSG_WINDOW;


/**
 * Sends stop when the credits run out, and resume when the receiver has
 * processed some and handed them back.
 */
UCS_TEST_P(test_cxi_fc_credits, sends_block_without_credits_then_resume)
{
    count_receives();
    cxi_connect(sender(), 0, receiver());
    uct_ep_h        ep   = sender().ep(0);
    uct_cxi_peer_t *peer = peer_of(sender(), 0);
    ASSERT_EQ(UCT_CXI_PEER_UP, peer->state);
    EXPECT_EQ((int)MSG_WINDOW, peer->tx.avail_slots);

    /* The receiver never runs, so processes nothing and returns nothing. */
    unsigned     sent = 0;
    ucs_status_t st;
    while ((st = send_short(ep)) == UCS_OK) {
        ASSERT_LE(++sent, 10 * MSG_WINDOW) << "credits never ran out";
    }
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, st);
    EXPECT_EQ(MSG_WINDOW, sent) << "exactly the window may be outstanding";
    EXPECT_EQ(0, peer->tx.avail_slots);

    for (unsigned i = 0; i < 1000; i++) {
        uct_iface_progress(sender().iface());
    }
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, send_short(ep))
            << "the sender alone cannot create credits";

    /* The receiver processes the messages, which hands the credits back. */
    ASSERT_TRUE(progress_until([&]() { return m_received == sent; }));
    ASSERT_TRUE(progress_until([&]() { return peer->tx.avail_slots > 0; }))
            << "no credits came back";
    EXPECT_EQ(UCS_OK, send_short(ep));
}

/**
 * A credit grant that finds the TX queue full waits, and goes when there is
 * room again, with nothing else in flight to announce it (so it is the
 * timer's retry that sends it). Until then the sender has not got the
 * credits back.
 */
UCS_TEST_P(test_cxi_fc_credits, grant_waits_for_tx_room_then_goes)
{
    count_receives();
    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep     = sender().ep(0);
    uct_cxi_peer_t  *peer   = peer_of(sender(), 0);
    uct_cxi_iface_t *riface = cxi_iface(receiver());
    unsigned         saved  = riface->tx.max_inflight;
    unsigned         sent   = 0;

    /* As far as the receiver knows its TX queue has no room for a message. */
    riface->tx.max_inflight = 0;

    /* Half a window, the threshold at which the receiver owes a grant. */
    while (sent < MSG_WINDOW / 2) {
        ASSERT_UCS_OK(send_short(ep));
        sent++;
    }
    ASSERT_TRUE(progress_until([&]() { return m_received == sent; }));
    EXPECT_FALSE(ucs_list_is_empty(&riface->fc.grants))
            << "the receiver owes a grant it cannot send";

    ucs_time_t until = ucs_get_time() + ucs_time_from_msec(20);
    while (ucs_get_time() < until) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_EQ((int)(MSG_WINDOW - sent), peer->tx.avail_slots)
            << "credits came back although there was no room to send them";
    EXPECT_FALSE(ucs_list_is_empty(&riface->fc.grants));

    riface->tx.max_inflight = saved;
    ASSERT_TRUE(progress_until([&]() {
        return peer->tx.avail_slots == (int)MSG_WINDOW;
    })) << "the waiting grant was never sent";
    EXPECT_TRUE(ucs_list_is_empty(&riface->fc.grants));
}

/**
 * A send that found no credits and was parked on the pending queue runs by
 * itself when credits come back -- through the arbiter, not by being retried
 * by hand.
 */
struct fc_pending_send {
    uct_pending_req_t        req;
    test_cxi_fc_credits     *test;
    uct_ep_h                 ep;
    bool                     done;
};

static ucs_status_t fc_pending_send_cb(uct_pending_req_t *self)
{
    fc_pending_send *p = ucs_container_of(self, fc_pending_send, req);
    ucs_status_t     st = p->test->send_short(p->ep);

    p->done = (st == UCS_OK);
    return st;
}

UCS_TEST_P(test_cxi_fc_credits, pending_send_resumes_when_credits_return)
{
    count_receives();
    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    unsigned sent = 0;
    while (send_short(ep) == UCS_OK) {
        ASSERT_LE(++sent, 10 * MSG_WINDOW);
    }

    fc_pending_send ps;
    ps.req.func = fc_pending_send_cb;
    ps.test     = this;
    ps.ep       = ep;
    ps.done     = false;
    ASSERT_UCS_OK(uct_ep_pending_add(ep, &ps.req, 0));

    /* Out of credits: the request stays parked however long the sender runs. */
    for (unsigned i = 0; i < 1000; i++) {
        uct_iface_progress(sender().iface());
    }
    EXPECT_FALSE(ps.done);

    ASSERT_TRUE(progress_until([&]() { return ps.done; }))
            << "the parked send never resumed after credits were returned";
    ASSERT_TRUE(progress_until([&]() { return m_received == sent + 1; }));
}

/**
 * Credits are conserved: after a long exchange, everything the sender spent is
 * exactly what the receiver processed, and the sender's view of what it was
 * handed back never gets ahead of that.
 */
UCS_TEST_P(test_cxi_fc_credits, credits_are_conserved)
{
    static const unsigned TOTAL = 200;

    count_receives();
    cxi_connect(sender(), 0, receiver());
    uct_ep_h        ep   = sender().ep(0);
    uct_cxi_peer_t *tx   = peer_of(sender(), 0);
    uct_cxi_peer_t *rx   = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, rx);

    unsigned sent = 0;
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(10.0);
    while ((sent < TOTAL) && (ucs_get_time() < deadline)) {
        if (send_short(ep) == UCS_OK) {
            sent++;
        }
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_EQ(TOTAL, sent);
    ASSERT_TRUE(progress_until([&]() { return m_received == TOTAL; }));

    EXPECT_EQ(TOTAL, tx->tx.used_slots);
    EXPECT_EQ(rx->rx.ret_slots, tx->tx.used_slots)
            << "the receiver must have processed exactly what was spent";
    EXPECT_EQ(rx->rx.ret_units[UCT_CXI_FC_AM], tx->tx.used_units[UCT_CXI_FC_AM]);

    /* The sender has been handed back no more than was processed, and what it
     * has not been handed is below a grant threshold (else a GRANT is due, and
     * may still be on its way). */
    unsigned threshold = cxi_iface(receiver())->fc.grant_slots;
    ASSERT_TRUE(progress_until([&]() {
        return (uint32_t)(rx->rx.ret_slots - tx->tx.ret_slots) < threshold;
    })) << "a grant was due but never arrived";
    EXPECT_LE((int32_t)(tx->tx.ret_slots - rx->rx.ret_slots), 0);
    EXPECT_EQ((int32_t)MSG_WINDOW,
              tx->tx.avail_slots + (int32_t)(tx->tx.used_slots - tx->tx.ret_slots));
}

/**
 * Event slots are one pool for every class of message; buffer space is a pool
 * of its own for each. Tag sends are not charged yet, so the charges are made
 * by hand, against a tag pool filled in by hand.
 */
UCS_TEST_P(test_cxi_fc_credits, slots_are_shared_and_buffer_space_is_per_class)
{
    cxi_connect(sender(), 0, receiver());

    uct_cxi_ep_t    *ep    = ucs_derived_of(sender().ep(0), uct_cxi_ep_t);
    uct_cxi_iface_t *iface = cxi_iface(sender());
    uct_cxi_peer_t  *peer  = ep->peer;
    const int32_t    slots = peer->tx.avail_slots;
    const int32_t    am    = peer->tx.avail_units[UCT_CXI_FC_AM];
    int              credited;

    ASSERT_EQ((int32_t)MSG_WINDOW, slots);
    peer->tx.avail_units[UCT_CXI_FC_TAG] = 100;

    /* A tag message that needs more tag space than there is waits, although
     * there are slots and Active Message space for it. */
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG, 2, 101, &credited));
    EXPECT_TRUE(iface->tx.credit_block);
    iface->tx.credit_block = 0;

    /* One that fits is charged its two slots and its tag space, nothing of
     * the Active Message pool. */
    ASSERT_EQ(UCS_OK,
              uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG, 2, 100, &credited));
    EXPECT_TRUE(credited);
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_TAG, 2, 100);
    EXPECT_EQ(slots - 2, peer->tx.avail_slots);
    EXPECT_EQ(0, peer->tx.avail_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(am, peer->tx.avail_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(2u, peer->tx.used_slots);
    EXPECT_EQ(100u, peer->tx.used_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(0u, peer->tx.used_units[UCT_CXI_FC_AM]);

    /* Another tag message is out of tag space; an Active Message is not, and
     * it takes its slot from the same pool the tag message did. */
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG, 2, 1, &credited));
    iface->tx.credit_block = 0;
    ASSERT_EQ(UCS_OK,
              uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_AM, 1, 1, &credited));
    uct_cxi_fc_debit(ep, credited, UCT_CXI_FC_AM, 1, 1);
    EXPECT_EQ(slots - 3, peer->tx.avail_slots);
    EXPECT_EQ(am - 1, peer->tx.avail_units[UCT_CXI_FC_AM]);

    /* And slots run out for everyone together. */
    peer->tx.avail_slots = 1;
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_cxi_fc_reserve(ep, iface, UCT_CXI_FC_TAG, 2, 0, &credited));
    iface->tx.credit_block = 0;
    peer->tx.avail_slots = slots - 3;

    /* A refund puts each charge back where it came from. */
    uct_cxi_fc_refund(iface, ep, UCT_CXI_FC_TAG, 2, 100);
    uct_cxi_fc_refund(iface, ep, UCT_CXI_FC_AM, 1, 1);
    EXPECT_EQ(slots, peer->tx.avail_slots);
    EXPECT_EQ(100, peer->tx.avail_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(am, peer->tx.avail_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(0u, peer->tx.used_slots);
    EXPECT_EQ(0u, peer->tx.used_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(0u, peer->tx.used_units[UCT_CXI_FC_AM]);
}

/**
 * Credits ride for free on a message going the other way: with a window large
 * enough that no GRANT is due, an Active Message from the receiver back to the
 * sender is what delivers them.
 */
class test_cxi_fc_piggyback : public test_cxi_fc_credits {
public:
    void init() override
    {
        modify_config("CXI_FC_MSG_WINDOW", "64"); /* GRANT only after 32 */
        m_received = 0;
        test_cxi_rma_base::init();
    }
};

UCS_TEST_P(test_cxi_fc_piggyback, credits_ride_on_a_reverse_message)
{
    static const unsigned N = 5;

    count_receives();
    unsigned back = 0;
    ASSERT_UCS_OK(uct_iface_set_am_handler(sender().iface(), AM_ID,
                                           count_am_handler, &back, 0));
    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_cxi_peer_t *tx = peer_of(sender(), 0);

    for (unsigned i = 0; i < N; i++) {
        ASSERT_EQ(UCS_OK, send_short(sender().ep(0)));
    }
    ASSERT_TRUE(progress_until([&]() { return m_received == N; }));

    /* Nothing is due yet, so nothing has been handed back. */
    for (unsigned i = 0; i < 1000; i++) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_EQ(0u, tx->tx.ret_slots);

    /* A message from the receiver carries them. */
    uint64_t payload = 0;
    ASSERT_UCS_OK(uct_ep_am_short(receiver().ep(0), AM_ID, 0, &payload,
                                  sizeof(payload)));
    ASSERT_TRUE(progress_until([&]() { return back == 1; }));
    EXPECT_EQ(N, tx->tx.ret_slots) << "the piggybacked credits were not applied";
    EXPECT_EQ((int32_t)64, tx->tx.avail_slots);
}

/**
 * Every counter a peer owes rides on a message going the other way, not only
 * the Active Message ones: event slots, and the buffer space of each class.
 * Nothing is sent from the sender here; what the receiver owes is set by hand,
 * as if it had processed that much.
 */
UCS_TEST_P(test_cxi_fc_piggyback, every_counter_rides_a_reverse_message)
{
    unsigned back = 0;

    ASSERT_UCS_OK(uct_iface_set_am_handler(sender().iface(), AM_ID,
                                           count_am_handler, &back, 0));
    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_cxi_peer_t *tx = peer_of(sender(), 0);
    uct_cxi_peer_t *rx = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, rx);

    const int32_t slots = tx->tx.avail_slots;
    const int32_t am    = tx->tx.avail_units[UCT_CXI_FC_AM];
    const int32_t tag   = tx->tx.avail_units[UCT_CXI_FC_TAG];
    ASSERT_GT(tag, 0) << "the CREP did not grant a tag pool";

    rx->rx.ret_slots                 += 3;
    rx->rx.ret_units[UCT_CXI_FC_AM]  += 5;
    rx->rx.ret_units[UCT_CXI_FC_TAG] += 7;

    uint64_t payload = 0;
    ASSERT_UCS_OK(uct_ep_am_short(receiver().ep(0), AM_ID, 0, &payload,
                                  sizeof(payload)));
    ASSERT_TRUE(progress_until([&]() { return back == 1; }));

    EXPECT_EQ(3u, tx->tx.ret_slots);
    EXPECT_EQ(5u, tx->tx.ret_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(7u, tx->tx.ret_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(slots + 3, tx->tx.avail_slots);
    EXPECT_EQ(am + 5, tx->tx.avail_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(tag + 7, tx->tx.avail_units[UCT_CXI_FC_TAG]);

    /* The receiver now counts all of it as told. */
    EXPECT_EQ(rx->rx.ret_slots, rx->rx.adv_slots);
    EXPECT_EQ(rx->rx.ret_units[UCT_CXI_FC_AM], rx->rx.adv_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(rx->rx.ret_units[UCT_CXI_FC_TAG],
              rx->rx.adv_units[UCT_CXI_FC_TAG]);
}

/**
 * A pure GRANT carries the same counters, whole.
 */
UCS_TEST_P(test_cxi_fc_piggyback, grant_carries_every_counter)
{
    cxi_connect(sender(), 0, receiver());
    uct_cxi_peer_t *tx = peer_of(sender(), 0);
    uct_cxi_peer_t *rx = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, rx);

    const int32_t tag = tx->tx.avail_units[UCT_CXI_FC_TAG];

    rx->rx.ret_slots                 += 3;
    rx->rx.ret_units[UCT_CXI_FC_AM]  += 5;
    rx->rx.ret_units[UCT_CXI_FC_TAG] += 7;
    uct_cxi_fc_grant_wanted(cxi_iface(receiver()), rx);

    ASSERT_TRUE(progress_until([&]() {
        return tx->tx.ret_units[UCT_CXI_FC_TAG] == 7u;
    })) << "the GRANT did not arrive";
    EXPECT_EQ(3u, tx->tx.ret_slots);
    EXPECT_EQ(5u, tx->tx.ret_units[UCT_CXI_FC_AM]);
    EXPECT_EQ(tag + 7, tx->tx.avail_units[UCT_CXI_FC_TAG]);
    ASSERT_TRUE(progress_until([&]() {
        return rx->rx.acked_units[UCT_CXI_FC_TAG] == 7u;
    })) << "the GRANT's delivery was not recorded";
}

/**
 * No window is too large for the counters: a window of 1 GiB (far above what
 * 17 bits can tell apart) is counted in granules instead. What a piggyback
 * carries is rounded down to a granule and the rest stays owed, until a GRANT
 * says it exactly.
 */
class test_cxi_fc_large_window : public test_cxi_fc_piggyback {
public:
    void init() override
    {
        modify_config("CXI_FC_TAG_BYTE_WINDOW", "1g");
        m_received = 0;
        test_cxi_rma_base::init();
    }
};

UCS_TEST_P(test_cxi_fc_large_window, counters_are_carried_in_granules)
{
    static const unsigned SHIFT = 9; /* 2^24 units: 2^15 granules of 2^9 */
    unsigned back = 0;

    ASSERT_UCS_OK(uct_iface_set_am_handler(sender().iface(), AM_ID,
                                           count_am_handler, &back, 0));
    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_cxi_peer_t *tx = peer_of(sender(), 0);
    uct_cxi_peer_t *rx = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, rx);

    const uint32_t window = 1u << 24;
    ASSERT_EQ(window, cxi_iface(receiver())->fc.unit_window[UCT_CXI_FC_TAG]);
    ASSERT_EQ((int32_t)window, tx->tx.avail_units[UCT_CXI_FC_TAG])
            << "the CREP did not carry the whole window";
    EXPECT_EQ(SHIFT, (unsigned)tx->pb_shift[1 + UCT_CXI_FC_TAG]);
    EXPECT_EQ(0u, (unsigned)tx->pb_shift[1 + UCT_CXI_FC_AM]);
    EXPECT_EQ(0u, (unsigned)tx->pb_shift[0]);

    uint64_t payload = 0;

    /* Less than a granule: nothing is worth sending. */
    rx->rx.ret_units[UCT_CXI_FC_TAG] = 100;
    ASSERT_UCS_OK(uct_ep_am_short(receiver().ep(0), AM_ID, 0, &payload,
                                  sizeof(payload)));
    ASSERT_TRUE(progress_until([&]() { return back == 1; }));
    EXPECT_EQ(0u, tx->tx.ret_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(0u, rx->rx.adv_units[UCT_CXI_FC_TAG]);

    /* Two and a bit granules: the two go, the bit stays owed. */
    rx->rx.ret_units[UCT_CXI_FC_TAG] = (2u << SHIFT) + 100;
    ASSERT_UCS_OK(uct_ep_am_short(receiver().ep(0), AM_ID, 0, &payload,
                                  sizeof(payload)));
    ASSERT_TRUE(progress_until([&]() { return back == 2; }));
    EXPECT_EQ(2u << SHIFT, tx->tx.ret_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(window + (2u << SHIFT),
              (uint32_t)tx->tx.avail_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(2u << SHIFT, rx->rx.adv_units[UCT_CXI_FC_TAG]);

    /* A GRANT is exact, and the sender takes it from there. */
    uct_cxi_fc_grant_wanted(cxi_iface(receiver()), rx);
    ASSERT_TRUE(progress_until([&]() {
        return tx->tx.ret_units[UCT_CXI_FC_TAG] == (2u << SHIFT) + 100;
    })) << "the GRANT did not arrive";
    EXPECT_EQ(window + (2u << SHIFT) + 100,
              (uint32_t)tx->tx.avail_units[UCT_CXI_FC_TAG]);

    /* A piggyback after that, short of the next granule, adds nothing and
     * does not take back what the GRANT told. */
    rx->rx.ret_units[UCT_CXI_FC_TAG] += 10;
    ASSERT_UCS_OK(uct_ep_am_short(receiver().ep(0), AM_ID, 0, &payload,
                                  sizeof(payload)));
    ASSERT_TRUE(progress_until([&]() { return back == 3; }));
    EXPECT_EQ((2u << SHIFT) + 100, tx->tx.ret_units[UCT_CXI_FC_TAG]);
}

/**
 * A byte window of four maximum-size messages, with plenty of message credits.
 */
class test_cxi_fc_bytes : public test_cxi_fc_credits {
public:
    void init() override
    {
        modify_config("CXI_FC_BYTE_WINDOW", "32k");
        m_received = 0;
        test_cxi_rma_base::init();
    }
};

/**
 * Byte credits limit large sends independently of the message count.
 */
UCS_TEST_P(test_cxi_fc_bytes, byte_credits_limit_large_sends)
{
    const size_t len      = sender().iface_attr().cap.am.max_zcopy;
    unsigned     received = 0;

    ASSERT_EQ(8192u, len);
    ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), 1,
                                           count_am_handler, &received, 0));
    cxi_connect(sender(), 0, receiver());
    uct_ep_h        ep   = sender().ep(0);
    uct_cxi_peer_t *peer = peer_of(sender(), 0);

    ASSERT_EQ(32u * 1024 / UCT_CXI_FC_UNIT, (unsigned)peer->tx.avail_units[UCT_CXI_FC_AM]);

    std::vector<uint8_t> buf(len, 0x5A);
    uct_mem_h            memh = reg(sender(), buf.data(), len);
    uct_iov_t            iov  = {buf.data(), len, memh, 0, 1};

    unsigned     sent = 0;
    ucs_status_t st;
    while ((st = uct_ep_am_zcopy(ep, 1, NULL, 0, &iov, 1, 0, NULL)) ==
           UCS_INPROGRESS) {
        ASSERT_LE(++sent, 16u);
    }
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, st);
    EXPECT_EQ(4u, sent) << "the byte window holds four";
    EXPECT_EQ(0, peer->tx.avail_units[UCT_CXI_FC_AM]);
    EXPECT_GT(peer->tx.avail_slots, 0) << "messages, not bytes, ran out";

    ASSERT_TRUE(progress_until([&]() { return received == sent; }));
    ASSERT_TRUE(progress_until([&]() {
        return peer->tx.avail_units[UCT_CXI_FC_AM] >= (int32_t)UCT_CXI_FC_UNITS(len);
    })) << "byte credits never came back";
    EXPECT_EQ(UCS_INPROGRESS,
              uct_ep_am_zcopy(ep, 1, NULL, 0, &iov, 1, 0, NULL));
    ASSERT_TRUE(progress_until([&]() { return received == sent + 1; }));

    /* Completions are delivered through progress, so drain them. */
    ASSERT_TRUE(progress_until([&]() {
        return cxi_iface(sender())->tx.outstanding == 0;
    }));
    dereg(sender(), memh);
}

/**
 * A send that never reaches the target's software is refunded: the target will
 * not hand back credits for a message it never processed.
 *
 * The receiver's AM PTE is disabled, so the sender's messages are accepted
 * locally and then completed with PT_DISABLED.
 */
UCS_TEST_P(test_cxi_fc_credits, failed_send_is_refunded)
{
    count_receives();
    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep    = sender().ep(0);
    uct_cxi_peer_t  *peer  = peer_of(sender(), 0);
    uct_cxi_iface_t *siface = cxi_iface(sender());
    uct_cxi_iface_t *riface = cxi_iface(receiver());

    struct c_set_state_cmd ss = {};
    ss.command.opcode = C_CMD_TGT_SETSTATE;
    ss.ptlte_index    = riface->am.pte->ptn;
    ss.ptlte_state    = C_PTLTE_DISABLED;
    ASSERT_EQ(UCS_OK, uct_cxi_iface_tgt_post(riface, &ss));
    usleep(100000); /* let the PTE reach the disabled state */

    {
        /* Each failed send is logged as an error by the sender, and the
         * receiver's PTE logs its state changes as warnings. */
        scoped_log_handler wrap_err(wrap_errors_logger);
        scoped_log_handler wrap_warn(wrap_warns_logger);

        for (unsigned i = 0; i < 3; i++) {
            ASSERT_EQ(UCS_OK, send_short(ep));
        }
        EXPECT_EQ((int)MSG_WINDOW - 3, peer->tx.avail_slots)
                << "charged when sent";

        ASSERT_TRUE(progress_until([&]() { return siface->tx.outstanding == 0; }));

        /* Let the receiver finish re-enabling its PTE while still wrapped. */
        ucs_time_t until = ucs_get_time() + ucs_time_from_sec(0.5);
        while (ucs_get_time() < until) {
            uct_iface_progress(receiver().iface());
        }
    }

    EXPECT_EQ((int)MSG_WINDOW, peer->tx.avail_slots)
            << "a send that never arrived must give its credits back";
    EXPECT_EQ(0u, peer->tx.used_slots);
    EXPECT_EQ(0u, m_received);
}


/* ------------------------------------------------------------------------
 * A Put the NIC could not place
 * ------------------------------------------------------------------------
 */

struct ring_rx_t {
    unsigned received;
    unsigned wrong_length;
};

static const size_t RING_MSG_LEN = 100 * 1024;

static ucs_status_t ring_am_handler(void *arg, void *data, size_t length,
                                    unsigned flags)
{
    ring_rx_t *rx = static_cast<ring_rx_t*>(arg);

    rx->received++;
    if (length != RING_MSG_LEN) {
        rx->wrong_length++;
    }
    return UCS_OK;
}

/**
 * A sender that is configured to send larger messages than the receiver is
 * (AM_MAX_ZCOPY differs): the receiver's buffers only keep room for what it
 * expects, so a message too big for the tail of the buffer it matched is not
 * placed.
 */
class test_cxi_fc_ring : public test_cxi_fc {
public:
    void init() override
    {
        modify_config("CXI_FC_BYTE_WINDOW", "4m");
        modify_config("CXI_FC_ACTIVE_SENDERS", "1");
        uct_test::init();

        modify_config("CXI_AM_MAX_ZCOPY", "128k");
        m_entities.push_back(uct_test::create_entity(0)); /* sender   */
        modify_config("CXI_AM_MAX_ZCOPY", "8k");
        m_entities.push_back(uct_test::create_entity(0)); /* receiver */
    }
};

/**
 * A message the NIC cannot place in the buffer it matched is reported to the
 * receiver as a failed Put with no data. It is not an Active Message: the
 * handler must not see it, and no credit may be returned for it (the sender
 * takes its own back when its ACK reports the failure).
 *
 * How many of the messages fail depends on how the receive buffers are laid
 * out, so this checks what must hold either way, not a count.
 */
UCS_TEST_P(test_cxi_fc_ring, failed_put_is_not_delivered)
{
    static const unsigned N = 14;
    ring_rx_t             rx = {0, 0};

    /* The failures are logged by both sides. */
    scoped_log_handler wrap_err(wrap_errors_logger);

    ASSERT_GE(sender().iface_attr().cap.am.max_zcopy, RING_MSG_LEN);
    ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), 1,
                                           ring_am_handler, &rx, 0));
    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep     = sender().ep(0);
    uct_cxi_peer_t  *tx     = peer_of(sender(), 0);
    uct_cxi_peer_t  *rxpeer = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, rxpeer);

    std::vector<uint8_t> buf(RING_MSG_LEN, 0x5A);
    uct_mem_h            memh = reg(sender(), buf.data(), RING_MSG_LEN);
    uct_iov_t            iov  = {buf.data(), RING_MSG_LEN, memh, 0, 1};

    for (unsigned i = 0; i < N; i++) {
        ASSERT_EQ(UCS_INPROGRESS,
                  uct_ep_am_zcopy(ep, 1, NULL, 0, &iov, 1, 0, NULL));
    }

    /* Let every completion and target event run its course. */
    ASSERT_TRUE(progress_until([&]() {
        return cxi_iface(sender())->tx.outstanding == 0;
    }));
    ucs_time_t until = ucs_get_time() + ucs_time_from_sec(0.5);
    while (ucs_get_time() < until) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }

    /* The sender gave back what failed, so what it still has charged is what
     * got through -- which is what the handler saw, whole. */
    unsigned delivered = tx->tx.used_slots;
    EXPECT_GE(delivered, 1u) << "the first message always fits";
    EXPECT_LT(delivered, N) << "the tail of the buffer should have run out";
    EXPECT_EQ(delivered, rx.received)
            << "the handler saw a message that did not arrive";
    EXPECT_EQ(0u, rx.wrong_length) << "a failed Put reached the handler";

    /* Credits come back only for what was processed. */
    EXPECT_EQ(rx.received, rxpeer->rx.ret_slots);
    EXPECT_EQ((int32_t)cxi_iface(receiver())->fc.slot_window,
              tx->tx.avail_slots + (int32_t)(tx->tx.used_slots -
                                            tx->tx.ret_slots));

    dereg(sender(), memh);
}

_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_credits, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_bytes, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_piggyback, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_large_window, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_ring, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_timeout, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_legacy, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_off, cxi)

#endif /* UCT_CXI_DISABLE_FC */
