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


/**
 * Two entities on the same node, each with its own iface and so its own
 * network identity: a handshake between them runs over the real control PTE.
 */
class test_cxi_fc : public test_cxi_rma_base {
protected:
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

    uct_cxi_iface_t *riface = cxi_iface(receiver());
    EXPECT_EQ(riface->fc.msg_window, peer->msg_window);
    EXPECT_EQ(riface->fc.unit_window, peer->unit_window);
    EXPECT_EQ(riface->fc.epoch & 0xffffff, peer->remote_epoch);

    /* The target knows the initiator, but has started nothing of its own. */
    uct_cxi_peer_t *back = find_peer(receiver(), sender());
    ASSERT_NE(nullptr, back) << "target never recorded the initiator";
    EXPECT_EQ(cxi_iface(sender())->fc.epoch, back->rx_epoch);
    EXPECT_EQ(UCT_CXI_PEER_DOWN, back->state);
    EXPECT_TRUE(ucs_list_is_empty(&back->connecting));
    EXPECT_TRUE(ucs_list_is_empty(&cxi_iface(sender())->fc.connecting));
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
    EXPECT_TRUE(ucs_list_is_empty(&cxi_iface(sender())->fc.connecting));
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

_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_legacy, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_fc_off, cxi)

#endif /* UCT_CXI_DISABLE_FC */
