/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * Shared fixture base for CXI RMA tests.
 *
 * Provides the two-entity setup (sender at index 0, receiver at index 1),
 * memory registration / deregistration helpers, rkey packing, and a
 * poll-until-flush helper.  Both test_cxi_ep and test_cxi_rma inherit from
 * this class.
 */

#ifndef UCT_TEST_CXI_RMA_H
#define UCT_TEST_CXI_RMA_H

#include <uct/api/uct.h>
#include <common/test.h>
#include <uct/uct_test.h>

#include <uct/cxi/base/cxi_ep.h>
#include <uct/cxi/base/cxi_iface.h>

#include <string>
#include <vector>


/**
 * Connect @a from's endpoint @a idx to @a to's iface, and wait for the
 * connection to be usable.
 *
 * A new endpoint handshakes with its peer, and until that completes an Active
 * Message cannot be sent (it returns UCS_ERR_NO_RESOURCE, and UCP parks the
 * send on its pending queue until the peer is up). UCT tests send straight
 * after connecting, so they use this to get the same effect: both ifaces are
 * progressed until the handshake is over. Tests of the handshake itself, or of
 * what happens before it finishes, call connect_to_iface() directly.
 */
template<typename Entity>
static inline void cxi_connect(Entity &from, unsigned idx, Entity &to)
{
    from.connect_to_iface(idx, to);

#ifndef UCT_CXI_DISABLE_FC
    uct_cxi_peer_t *peer     = ucs_derived_of(from.ep(idx), uct_cxi_ep_t)->peer;
    ucs_time_t      deadline = ucs_get_time() + ucs_time_from_sec(5.0);

    while ((peer != NULL) &&
           ((peer->state == UCT_CXI_PEER_DOWN) ||
            (peer->state == UCT_CXI_PEER_CREQ_SENT)) &&
           (ucs_get_time() < deadline)) {
        uct_iface_progress(from.iface());
        uct_iface_progress(to.iface());
    }

    EXPECT_TRUE((peer == NULL) || ((peer->state != UCT_CXI_PEER_DOWN) &&
                                   (peer->state != UCT_CXI_PEER_CREQ_SENT)))
            << "handshake with the peer did not finish";
#endif
}


#ifndef UCT_CXI_DISABLE_FC

/** The record \a ent's iface holds for the iface of \a remote, or NULL. */
template<typename Entity>
static inline uct_cxi_peer_t *cxi_find_peer(Entity &ent, Entity &remote)
{
    uct_cxi_iface_t *iface  = ucs_derived_of(ent.iface(), uct_cxi_iface_t);
    uct_cxi_iface_t *riface = ucs_derived_of(remote.iface(), uct_cxi_iface_t);
    uint32_t         key    = CXI_MATCH_ID(uct_cxi_iface_md(iface)->pid_bits,
                                           riface->domain->pid,
                                           uct_cxi_iface_md(riface)->
                                                   device.nid);
    khiter_t         iter   = kh_get(uct_cxi_peer_hash, &iface->fc.peers, key);

    return (iter == kh_end(&iface->fc.peers)) ?
           NULL : kh_value(&iface->fc.peers, iter);
}

/**
 * Once everything \a from sent to \a to has been dealt with, what \a from
 * was charged for it and what \a to has given back agree, in every pool: no
 * credit was lost, none made up. A message may still be on its way, so both are
 * progressed until they agree, for at most \a timeout_sec. (What the
 * receiver owes has not necessarily reached the sender: that is a matter of
 * grants, not of whether the credits were given back.)
 */
template<typename Entity>
static inline void cxi_expect_conserved(Entity &from, Entity &to,
                                        double timeout_sec = 5.0)
{
    uct_cxi_peer_t *tx = ucs_derived_of(from.ep(0), uct_cxi_ep_t)->peer;
    uct_cxi_peer_t *rx = cxi_find_peer(to, from);

    ASSERT_NE(nullptr, tx);
    ASSERT_NE(nullptr, rx);

    auto conserved = [&]() {
        return (tx->tx.used_slots == rx->rx.ret_slots) &&
               (tx->tx.used_units[UCT_CXI_FC_AM] ==
                rx->rx.ret_units[UCT_CXI_FC_AM]) &&
               (tx->tx.used_units[UCT_CXI_FC_TAG] ==
                rx->rx.ret_units[UCT_CXI_FC_TAG]);
    };
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);

    while (!conserved() && (ucs_get_time() < deadline)) {
        uct_iface_progress(from.iface());
        uct_iface_progress(to.iface());
    }

    EXPECT_EQ(tx->tx.used_slots, rx->rx.ret_slots) << "event slots";
    EXPECT_EQ(tx->tx.used_units[UCT_CXI_FC_AM],
              rx->rx.ret_units[UCT_CXI_FC_AM]) << "Active Message space";
    EXPECT_EQ(tx->tx.used_units[UCT_CXI_FC_TAG],
              rx->rx.ret_units[UCT_CXI_FC_TAG]) << "tag matching space";
}

#endif /* UCT_CXI_DISABLE_FC */


/**
 * test_cxi_rma_base — two-entity fixture for CXI loopback tests.
 *
 * Sender EP (slot 0) is connected to the receiver's iface via
 * connect_to_iface() in each individual test.
 */
class test_cxi_rma_base : public uct_test {
protected:
    void init() override
    {
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(0)); /* sender   */
        m_entities.push_back(uct_test::create_entity(0)); /* receiver */
    }

    entity &sender()   { return m_entities.at(0); }
    entity &receiver() { return m_entities.at(1); }

    /** Register a host buffer on @a ent's MD with RMA access. */
    uct_mem_h reg(entity &ent, void *buf, size_t len)
    {
        uct_md_mem_reg_params_t p;
        p.field_mask = UCT_MD_MEM_REG_FIELD_FLAGS;
        p.flags      = UCT_MD_MEM_ACCESS_RMA;

        uct_mem_h memh = UCT_MEM_HANDLE_NULL;
        EXPECT_UCS_OK(uct_md_mem_reg_v2(ent.md(), buf, len, &p, &memh));
        return memh;
    }

    /** Deregister a previously registered buffer. */
    void dereg(entity &ent, uct_mem_h memh)
    {
        uct_md_mem_dereg_params_t p;
        p.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
        p.memh       = memh;
        EXPECT_UCS_OK(uct_md_mem_dereg_v2(ent.md(), &p));
    }

    /**
     * Pack the rkey for @a memh on @a ent's MD.
     * Returns the packed bytes; caller unpacks with uct_rkey_unpack().
     */
    std::string pack_rkey(entity &ent, uct_mem_h memh,
                          void *buf, size_t len)
    {
        std::string rkey_buf(ent.md_attr().rkey_packed_size, '\0');
        uct_md_mkey_pack_params_t p;
        p.field_mask = 0;
        EXPECT_UCS_OK(uct_md_mkey_pack_v2(ent.md(), memh, buf, len,
                                           &p, &rkey_buf[0]));
        return rkey_buf;
    }

    /**
     * Poll iface_progress + ep_flush on @a ent until all sends posted on
     * @a ep are acknowledged, or a 5-second deadline elapses.
     */
    void flush_ep(entity &ent, uct_ep_h ep)
    {
        ucs_time_t   deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        ucs_status_t status;

        do {
            uct_iface_progress(ent.iface());
            status = uct_ep_flush(ep, 0, NULL);
        } while (status == UCS_INPROGRESS &&
                 ucs_get_time() < deadline);

        ASSERT_EQ(UCS_OK, status) << "ep_flush timed out after 5 s";
    }
};

#endif /* UCT_TEST_CXI_RMA_H */
