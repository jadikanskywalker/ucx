/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching unit tests -- Phase A (eager only).
 *
 * Direct-match tests post a priority LE (tag_recv_zcopy) before sending, so
 * the message DMAs straight into the destination buffer with zero software
 * copy (C_EVENT_PUT with ptl_list==PRIORITY on the receiver).
 *
 * Unexpected-path tests send first with no priority LE posted, so the
 * message lands in the overflow ring and gets handed to eager_cb
 * (C_EVENT_PUT with ptl_list==OVERFLOW).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_tag.h"

#include <uct/cxi/base/cxi_ep.h>
#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>
extern "C" {
#include <uct/cxi/base/cxi_tag.h>
}

#include <cstring>
#include <functional>
#include <vector>
#include <unistd.h>


class test_cxi_tag : public test_cxi_tag_base {
protected:
    static uct_cxi_iface_t *cxi_iface(entity &e)
    {
        return ucs_derived_of(e.iface(), uct_cxi_iface_t);
    }
};


/* -------------------------------------------------------------------------
 * Direct match: priority LE already posted before the message arrives
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag, direct_match_short)
{
    static const uct_tag_t TAG     = 0x1122334455667788ULL;
    static const size_t    PAY_LEN = 64;
    static const uint8_t   FILL    = 0xA5;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx_buf.data(), PAY_LEN));

    poll_until(rctx.completed);
    EXPECT_TRUE(rctx.consumed);

    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(0ULL, rctx.imm) << "eager_short has no imm parameter (implicit 0)";
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }

    dereg(receiver(), rx_memh);
    flush_ep(sender(), ep);
}

UCS_TEST_P(test_cxi_tag, direct_match_bcopy)
{
    static const uct_tag_t TAG     = 0x2233445566778899ULL;
    static const uint64_t  IMM     = 0xCAFEBABEULL;
    static const size_t    PAY_LEN = 4096;
    static const uint8_t   FILL    = 0x5A;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    struct { uint8_t fill; size_t len; } arg = {FILL, PAY_LEN};
    auto pack = [](void *dst, void *a) -> size_t {
        auto *p = static_cast<decltype(arg) *>(a);
        memset(dst, p->fill, p->len);
        return p->len;
    };

    ssize_t ret = uct_ep_tag_eager_bcopy(ep, TAG, IMM, +pack, &arg, 0);
    ASSERT_EQ(static_cast<ssize_t>(PAY_LEN), ret);

    poll_until(rctx.completed);
    EXPECT_TRUE(rctx.consumed);

    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(IMM, rctx.imm);
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }

    dereg(receiver(), rx_memh);
    flush_ep(sender(), ep);
}

UCS_TEST_P(test_cxi_tag, direct_match_zcopy)
{
    static const uct_tag_t TAG     = 0x33445566778899AAULL;
    static const uint64_t  IMM     = 0xDEADBEEFULL;
    static const size_t    PAY_LEN = 8192;
    static const uint8_t   FILL    = 0x3C;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t riov;
    riov.buffer = rx_buf.data();
    riov.length = PAY_LEN;
    riov.memh   = rx_memh;
    riov.stride = 0;
    riov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &riov, 1,
                                           &rctx.super));

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    uct_mem_h            tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);

    uct_iov_t siov;
    siov.buffer = tx_buf.data();
    siov.length = PAY_LEN;
    siov.memh   = tx_memh;
    siov.stride = 0;
    siov.count  = 1;

    ucs_status_t st = uct_ep_tag_eager_zcopy(ep, TAG, IMM, &siov, 1, 0, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);

    poll_until(rctx.completed);
    EXPECT_TRUE(rctx.consumed);

    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(IMM, rctx.imm);
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }

    dereg(receiver(), rx_memh);
    flush_ep(sender(), ep);
    dereg(sender(), tx_memh);
}


/* -------------------------------------------------------------------------
 * Unexpected path: no priority LE posted, message lands in overflow ring
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag, unexpected_short)
{
    static const uct_tag_t TAG     = 0x445566778899AABBULL;
    static const size_t    PAY_LEN = 48;
    static const uint8_t   FILL    = 0x77;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx_buf.data(), PAY_LEN));

    poll_until(m_unexp.fired);

    EXPECT_EQ(TAG, m_unexp.tag);
    EXPECT_EQ(0ULL, m_unexp.imm);
    ASSERT_EQ(PAY_LEN, m_unexp.data.size());
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, m_unexp.data[i]) << "byte " << i << " mismatch";
    }

    flush_ep(sender(), ep);
}

UCS_TEST_P(test_cxi_tag, unexpected_bcopy)
{
    static const uct_tag_t TAG     = 0x5566778899AABBCCULL;
    static const uint64_t  IMM     = 0x1234ULL;
    static const size_t    PAY_LEN = 2048;
    static const uint8_t   FILL    = 0x99;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    struct { uint8_t fill; size_t len; } arg = {FILL, PAY_LEN};
    auto pack = [](void *dst, void *a) -> size_t {
        auto *p = static_cast<decltype(arg) *>(a);
        memset(dst, p->fill, p->len);
        return p->len;
    };

    ssize_t ret = uct_ep_tag_eager_bcopy(ep, TAG, IMM, +pack, &arg, 0);
    ASSERT_EQ(static_cast<ssize_t>(PAY_LEN), ret);

    poll_until(m_unexp.fired);

    EXPECT_EQ(TAG, m_unexp.tag);
    EXPECT_EQ(IMM, m_unexp.imm);
    ASSERT_EQ(PAY_LEN, m_unexp.data.size());
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, m_unexp.data[i]) << "byte " << i << " mismatch";
    }

    flush_ep(sender(), ep);
}

#ifndef UCT_CXI_DISABLE_FC

/**
 * A tag_eager_short is tracked until its ACK, like every other send (see
 * test_cxi_am.am_short_tracked_until_ack).
 */
UCS_TEST_P(test_cxi_tag, tag_eager_short_tracked_until_ack)
{
    static const uct_tag_t TAG = 0x1357924680ABCDEFULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep     = sender().ep(0);
    uct_cxi_ep_t    *cep    = ucs_derived_of(ep, uct_cxi_ep_t);
    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);

    uint8_t payload[16] = {};
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, payload, sizeof(payload)));

    EXPECT_EQ(1u, cep->outstanding);
    EXPECT_EQ(1u, siface->tx.outstanding);

    flush_ep(sender(), ep);
    EXPECT_EQ(0u, cep->outstanding);
    EXPECT_EQ(0u, siface->tx.outstanding);

    poll_until(m_unexp.fired);
    EXPECT_EQ(TAG, m_unexp.tag);
}

#endif /* UCT_CXI_DISABLE_FC */

/**
 * Several unexpected eager messages of very different sizes sharing the
 * overflow ring, none consumed before all have landed.
 *
 * eager_cb is handed each payload where it sits in the ring (no staging
 * copy), so every message must still arrive intact and with its own tag and
 * immediate even though later arrivals are landing next to it, and the large
 * ones push the ring through buffer rotations (auto-unlink and repost).
 */
UCS_TEST_P(test_cxi_tag, unexpected_burst_sizes)
{
    static const uct_tag_t TAG_BASE = 0x7700000000000000ULL;
    /* bcopy is limited to the bounce buffer size, zcopy goes up to the eager
     * limit. */
    static const size_t    BCOPY_SIZES[] = {1, 100, 1024, 8192};
    static const size_t    ZCOPY_SIZES[] = {100 * 1024, 250 * 1024};

    struct sent_msg {
        uct_tag_t            tag;
        std::vector<uint8_t> data;
        uct_mem_h            memh;
    };
    std::vector<sent_msg> sent;

    auto make_msg = [&](size_t len) {
        sent_msg m;
        m.tag  = TAG_BASE + sent.size();
        m.memh = NULL;
        m.data.resize(len);
        for (size_t i = 0; i < len; i++) {
            /* Unique per message and per position. */
            m.data[i] = static_cast<uint8_t>(sent.size() * 37 + i * 7 + 1);
        }
        return m;
    };

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    for (size_t len : BCOPY_SIZES) {
        sent.push_back(make_msg(len));
        sent_msg &m = sent.back();
        struct { const uint8_t *src; size_t len; } arg = {m.data.data(), len};
        auto pack = [](void *dst, void *a) -> size_t {
            auto *p = static_cast<decltype(arg) *>(a);
            memcpy(dst, p->src, p->len);
            return p->len;
        };
        ASSERT_EQ(static_cast<ssize_t>(len),
                  uct_ep_tag_eager_bcopy(ep, m.tag, m.tag ^ 0xFF, +pack, &arg,
                                         0));
    }

    for (size_t len : ZCOPY_SIZES) {
        sent.push_back(make_msg(len));
        sent_msg &m = sent.back();
        m.memh = reg(sender(), m.data.data(), len);
        uct_iov_t iov;
        iov.buffer = m.data.data();
        iov.length = len;
        iov.memh   = m.memh;
        iov.stride = 0;
        iov.count  = 1;
        ASSERT_EQ(UCS_INPROGRESS,
                  uct_ep_tag_eager_zcopy(ep, m.tag, m.tag ^ 0xFF, &iov, 1, 0,
                                         NULL));
    }

    /* Let everything land as genuinely unexpected before the receiver looks. */
    usleep(200000);

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(10.0);
    while ((m_unexp.all.size() < sent.size()) && (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_EQ(sent.size(), m_unexp.all.size());

    for (const sent_msg &m : sent) {
        const uct_cxi_tag_unexp_msg *got = NULL;
        for (const uct_cxi_tag_unexp_msg &r : m_unexp.all) {
            if (r.tag == m.tag) {
                got = &r;
            }
        }
        ASSERT_NE(nullptr, got) << "message with tag 0x" << std::hex << m.tag
                                << " never delivered";
        EXPECT_EQ(m.tag ^ 0xFF, got->imm);
        EXPECT_EQ(m.data, got->data)
                << "payload mismatch for " << std::dec << m.data.size()
                << "-byte message";
    }

    flush_ep(sender(), ep);
    for (sent_msg &m : sent) {
        if (m.memh != NULL) {
            dereg(sender(), m.memh);
        }
    }
}


/* -------------------------------------------------------------------------
 * Delayed match: message lands in overflow BEFORE a receive is posted for
 * it, so the eventual match is a hardware search-on-append (C_EVENT_
 * PUT_OVERFLOW), not a direct C_EVENT_PUT into an already-posted LE.
 *
 * This exists to answer one specific question, not exercised by any other
 * test here: for this delayed-match case, does the data actually land in
 * the POSTED receive's own buffer, or does uct_cxi_iface_tag_handle_
 * eager_match()'s current no-copy assumption ("data already sits in the
 * caller's own registered buffer", see its doc comment) leave the posted
 * buffer untouched? libfabric's own cxip_ux_send() (cxip_msg_hpc.c:593-640)
 * does an explicit memcpy for exactly this case, on the grounds that
 * Portals4 never retroactively re-targets an already-landed Put's DMA into
 * a later-posted LE -- suggesting our own code may have a real,
 * pre-existing correctness gap here. This test is the direct empirical
 * check, not a proxy for it.
 *
 * Deliberately does NOT call receiver-side progress until after the
 * receive is posted, so the arrival is guaranteed (by real elapsed time,
 * not by any progress call) to be sitting unresolved in the receiver's
 * overflow ring before uct_iface_tag_recv_zcopy ever runs -- calling
 * progress earlier would let today's code's unconditional eager_cb
 * hand-off (the separate, already-tracked double-completion race this
 * whole increment is fixing) race ahead and consume the arrival before
 * this test can pose its own question. This test does not assert on
 * whether eager_cb also spuriously fires -- that is the other, already-
 * understood bug, not what this test is checking.
 */
UCS_TEST_P(test_cxi_tag, delayed_match_data_copy)
{
    static const uct_tag_t TAG     = 0x1122334455667788ULL;
    static const size_t    PAY_LEN = 64;
    static const uint8_t   FILL    = 0x5C;
    static const uint8_t   SENTINEL = 0xEE; /* != FILL, so leftover sentinel
                                               * bytes are unambiguous */

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx_buf.data(), PAY_LEN));

    /* Real elapsed time, no progress calls on either side -- let the Put
     * actually land in the receiver's overflow ring before we do anything
     * that could drain either side's EQ. Same-NIC loopback, so this is
     * generous by a wide margin. */
    usleep(100000); /* 100 ms */

    std::vector<uint8_t> rx_buf(PAY_LEN, SENTINEL);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    poll_until(rctx.completed);

    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i])
                << "byte " << i << " mismatch -- rx_buf still holds the "
                   "SENTINEL fill (0x" << std::hex << (unsigned)SENTINEL
                << std::dec << ") if the delayed-match completion never "
                   "actually copied the data in";
    }

    dereg(receiver(), rx_memh);
    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * Truncation: posted buffer smaller than the sent message
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag, truncation)
{
    static const uct_tag_t TAG     = 0x66778899AABBCCDDULL;
    static const size_t    RX_LEN  = 32;
    static const size_t    TX_LEN  = 256;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rx_buf(RX_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), RX_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = RX_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    struct { uint8_t fill; size_t len; } arg = {0xEE, TX_LEN};
    auto pack = [](void *dst, void *a) -> size_t {
        auto *p = static_cast<decltype(arg) *>(a);
        memset(dst, p->fill, p->len);
        return p->len;
    };

    ssize_t ret = uct_ep_tag_eager_bcopy(ep, TAG, 0, +pack, &arg, 0);
    ASSERT_EQ(static_cast<ssize_t>(TX_LEN), ret);

    poll_until(rctx.completed);

    EXPECT_EQ(UCS_ERR_MESSAGE_TRUNCATED, rctx.status);
    EXPECT_EQ(RX_LEN, rctx.length) << "delivered length should be capped "
                                      "at the posted buffer size";

    dereg(receiver(), rx_memh);
    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * Cancel
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag, cancel_not_force)
{
    static const uct_tag_t TAG     = 0x778899AABBCCDDEEULL;
    static const size_t    PAY_LEN = 16;

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(), &rctx.super,
                                            0));

    poll_until(rctx.completed);
    EXPECT_EQ(UCS_ERR_CANCELED, rctx.status);

    dereg(receiver(), rx_memh);
}

UCS_TEST_P(test_cxi_tag, cancel_force)
{
    static const uct_tag_t TAG     = 0x8899AABBCCDDEEFFULL;
    static const size_t    PAY_LEN = 16;

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(), &rctx.super,
                                            1));

    /* force=1: completed_cb must NOT be invoked. Drain progress for a
     * short, bounded window and confirm it stays false. */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(1.0);
    while (ucs_get_time() < deadline) {
        uct_iface_progress(receiver().iface());
    }
    EXPECT_FALSE(rctx.completed) << "force cancel must not invoke completed_cb";

    /* Confirm the slot was actually reclaimed -- post and satisfy a fresh
     * recv on the same tag; if the earlier slot leaked, this would either
     * fail outright or (with enough repetitions) exhaust TAG_MAX_OUTSTANDING. */
    uct_cxi_tag_recv_ctx rctx2;
    init_recv_ctx(rctx2);
    uct_iov_t iov2;
    iov2.buffer = rx_buf.data();
    iov2.length = PAY_LEN;
    iov2.memh   = rx_memh;
    iov2.stride = 0;
    iov2.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov2, 1,
                                           &rctx2.super));
    ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(), &rctx2.super,
                                            1));

    dereg(receiver(), rx_memh);
}


/* -------------------------------------------------------------------------
 * Forced race: SEARCH_AND_DELETE vs. a real APPEND's search-on-append
 * -------------------------------------------------------------------------
 */

/*
 * Deliberately forces the actual race this whole SEARCH_AND_DELETE design
 * exists to arbitrate: a message's arrival into the overflow ring and a
 * matching uct_iface_tag_recv_zcopy()'s priority-LE APPEND, issued back to
 * back with no progress calls or delay in between -- close enough in real
 * time that which one Cassini processes first is not something this test
 * controls or knows in advance. Cassini's own mutual exclusion between a
 * real APPEND's search-on-append and our targeted SEARCH_AND_DELETE must
 * guarantee exactly one side ever wins against the same unexpected entry --
 * never both (the double-completion crash, job 100716) and never neither
 * (a silently dropped message). Alternates which of the two is issued
 * first across iterations, since real winner is up to Cassini's own
 * relative timing regardless of program order -- this only controls which
 * program-level interleaving is attempted, not the actual hardware race.
 */
UCS_TEST_P(test_cxi_tag, forced_race_search_delete_vs_priority_append)
{
    static const size_t ITERS   = 100;
    static const size_t PAY_LEN = 32;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    size_t priority_wins      = 0;
    size_t search_delete_wins = 0;

    for (size_t i = 0; i < ITERS; i++) {
        uct_tag_t tag  = 0xF00D000000000000ULL | i;
        uint8_t   fill = static_cast<uint8_t>(i);

        std::vector<uint8_t> rx_buf(PAY_LEN, 0);
        uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

        uct_cxi_tag_recv_ctx rctx;
        init_recv_ctx(rctx);

        uct_iov_t iov;
        iov.buffer = rx_buf.data();
        iov.length = PAY_LEN;
        iov.memh   = rx_memh;
        iov.stride = 0;
        iov.count  = 1;

        std::vector<uint8_t> tx_buf(PAY_LEN, fill);

        m_unexp.fired = false;

        if (i & 1) {
            /* Send first, post the receive immediately after -- races the
             * message's physical arrival against the APPEND. */
            ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, tag, tx_buf.data(),
                                                 PAY_LEN));
            ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), tag,
                                                   UCS_MASK(64), &iov, 1,
                                                   &rctx.super));
        } else {
            /* The other program-order interleaving -- the real winner is
             * still up to Cassini's own relative timing, not this order. */
            ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), tag,
                                                   UCS_MASK(64), &iov, 1,
                                                   &rctx.super));
            ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, tag, tx_buf.data(),
                                                 PAY_LEN));
        }

        /* Exactly one of these two must eventually become true. */
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        while (!rctx.completed && !m_unexp.fired &&
              (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_TRUE(rctx.completed || m_unexp.fired)
                << "iteration " << i << ": message vanished -- neither the "
                   "priority-LE match nor the unexpected path ever fired";

        if (rctx.completed) {
            priority_wins++;
            EXPECT_EQ(UCS_OK, rctx.status);
            EXPECT_EQ(tag, rctx.stag);
            EXPECT_EQ(PAY_LEN, rctx.length);
            for (size_t b = 0; b < PAY_LEN; b++) {
                EXPECT_EQ(fill, rx_buf[b])
                        << "iteration " << i << " byte " << b;
            }

            /* The receive completed via a real priority-LE match -- confirm
             * SEARCH_AND_DELETE did NOT also independently deliver this
             * same message a second time (the actual double-completion
             * bug). A short, bounded extra drain is enough: any spurious
             * eager_cb would already be sitting in the EQ by now, this
             * message's own processing is long done. */
            ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.2);
            while (ucs_get_time() < settle) {
                uct_iface_progress(sender().iface());
                uct_iface_progress(receiver().iface());
            }
            EXPECT_FALSE(m_unexp.fired)
                    << "iteration " << i << ": message delivered TWICE -- "
                       "both the priority-LE match and SEARCH_AND_DELETE "
                       "independently succeeded";
        } else {
            search_delete_wins++;
            EXPECT_EQ(tag, m_unexp.tag);
            ASSERT_EQ(PAY_LEN, m_unexp.data.size());
            for (size_t b = 0; b < PAY_LEN; b++) {
                EXPECT_EQ(fill, m_unexp.data[b])
                        << "iteration " << i << " byte " << b;
            }

            /* SEARCH_AND_DELETE won -- the priority LE this iteration
             * posted is still live (nothing else resolves it in this
             * outcome, see the design plan). Force-cancel to reclaim the
             * slot before the next iteration, matching cancel_force's own
             * precedent; completed_cb must never fire for a force-cancel. */
            ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                    &rctx.super, 1));
            ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.2);
            while (ucs_get_time() < settle) {
                uct_iface_progress(sender().iface());
                uct_iface_progress(receiver().iface());
            }
            EXPECT_FALSE(rctx.completed)
                    << "iteration " << i << ": force-cancelled receive's "
                       "completed_cb fired anyway";
        }

        dereg(receiver(), rx_memh);
    }

    UCS_TEST_MESSAGE << "priority_wins=" << priority_wins
                     << " search_delete_wins=" << search_delete_wins
                     << " / " << ITERS << " iterations";

    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * Unexpected messages and the receives posted for them: who takes which
 * -------------------------------------------------------------------------
 */

/*
 * Two messages with one tag arrive while the receiver is not looking, then a
 * receive is posted: hardware gives it the first, and the second is UCP's.
 * UCP must be told that the receive is taken before it is told of the second
 * message, or it can match the second to the receive (and cancel it, losing
 * the first), and told once.
 */
UCS_TEST_P(test_cxi_tag, claimed_receive_is_consumed_before_the_next_report)
{
    static const size_t    PAY_LEN = 32;
    static const uct_tag_t TAG     = 0xC1A1000000000001ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx1(PAY_LEN, 0x11), tx2(PAY_LEN, 0x22);
    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx1.data(), PAY_LEN));
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx2.data(), PAY_LEN));
    usleep(200000); /* both are in the overflow list before the receive */

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);
    m_unexp.watch = &rctx.consumed;

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &rctx.super));

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(10.0);
    while ((!rctx.completed || (m_unexp.all.size() < 1)) &&
           (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_TRUE(rctx.completed);
    ASSERT_EQ(1u, m_unexp.all.size());

    EXPECT_EQ(UCS_OK, rctx.status);
    EXPECT_EQ(tx1, rx_buf) << "the receive must get the first message";
    EXPECT_EQ(tx2, m_unexp.all[0].data) << "UCP must get the second";
    EXPECT_TRUE(m_unexp.all[0].watched_consumed)
            << "the second message was reported before UCP was told that the "
               "receive is taken";

    /* Nothing else shows up. */
    ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.2);
    while (ucs_get_time() < settle) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_EQ(1u, m_unexp.all.size());

    m_unexp.watch = NULL;
    flush_ep(sender(), ep);
    dereg(receiver(), rx_memh);
}


/*
 * More messages arrive than there are receives, as in tag_bw: all with one
 * tag, with UCP modelled by what it does with a message it is handed -- match
 * it to its oldest receive that is not consumed, and force-cancel that
 * receive -- and by what it does with a receive that is consumed (nothing,
 * but its message is the receive's). Every message must get to one place only:
 * a receive that hardware completed, or UCP.
 */
UCS_TEST_P(test_cxi_tag, more_messages_than_receives)
{
    static const unsigned  NUM_MSGS = 40;
    static const unsigned  NUM_RECV = 16;
    static const size_t    PAY_LEN  = 8;
    static const uct_tag_t TAG      = 0xC1A2000000000001ULL;

    struct model_recv {
        uct_cxi_tag_recv_ctx rctx;
        std::vector<uint8_t> buf;
        uct_mem_h            memh;
        bool                 sw_matched;
    };

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<model_recv> recvs(NUM_RECV);
    std::vector<unsigned>   seen(NUM_MSGS, 0);
    unsigned                to_ucp = 0;

    m_unexp.on_msg = [&](const uct_cxi_tag_unexp_msg &msg) {
        ASSERT_EQ(PAY_LEN, msg.data.size());
        unsigned id = msg.data[0];
        ASSERT_LT(id, NUM_MSGS);

        for (model_recv &r : recvs) {
            if (!r.rctx.consumed && !r.sw_matched && !r.rctx.completed) {
                /* What UCP does: complete the oldest expected receive with
                 * it, and give up its own hardware receive. */
                r.sw_matched = true;
                seen[id]++;
                ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                        &r.rctx.super, 1));
                return;
            }
        }
        seen[id]++;
        to_ucp++;
    };

    for (unsigned i = 0; i < NUM_MSGS; i++) {
        std::vector<uint8_t> tx(PAY_LEN, 0);
        tx[0] = i;
        ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx.data(), PAY_LEN));
    }
    usleep(500000); /* all of them are in the overflow list */

    for (model_recv &r : recvs) {
        r.buf.assign(PAY_LEN, 0xFF);
        r.memh       = reg(receiver(), r.buf.data(), PAY_LEN);
        r.sw_matched = false;
        init_recv_ctx(r.rctx);

        uct_iov_t iov;
        iov.buffer = r.buf.data();
        iov.length = PAY_LEN;
        iov.memh   = r.memh;
        iov.stride = 0;
        iov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                               UCS_MASK(64), &iov, 1,
                                               &r.rctx.super));
    }

    /* The messages the receives complete are theirs: counted by them. */
    auto hw_done = [&]() {
        unsigned n = 0;
        for (model_recv &r : recvs) {
            n += r.rctx.completed;
        }
        return n;
    };

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(10.0);
    while (((hw_done() + to_ucp) < NUM_MSGS) &&
           (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }

    for (model_recv &r : recvs) {
        if (r.rctx.completed) {
            ASSERT_EQ(PAY_LEN, r.rctx.length);
            ASSERT_LT(r.buf[0], NUM_MSGS);
            seen[r.buf[0]]++;
        }
    }

    unsigned cancelled = 0;
    for (model_recv &r : recvs) {
        cancelled += r.sw_matched;
    }
    EXPECT_EQ(0u, cancelled)
            << "UCP was handed a message while an unconsumed receive could "
               "still have taken another";
    EXPECT_EQ(NUM_RECV, hw_done());
    EXPECT_EQ(NUM_MSGS - NUM_RECV, to_ucp);
    for (unsigned i = 0; i < NUM_MSGS; i++) {
        EXPECT_EQ(1u, seen[i]) << "message " << i
                               << " was delivered " << seen[i] << " times";
    }

    m_unexp.on_msg = nullptr;
    flush_ep(sender(), ep);
    for (model_recv &r : recvs) {
        dereg(receiver(), r.memh);
    }
}


/*
 * A receive whose outcome is known (it matched directly, or was cancelled) stays
 * in the ring until a fence covers it, but is not for a later unexpected
 * message to take: the message goes to UCP.
 */
UCS_TEST_P(test_cxi_tag, spent_receive_does_not_claim)
{
    static const size_t    PAY_LEN = 16;
    static const uct_tag_t TAG     = 0xC1A4000000000001ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx1(PAY_LEN, 0x31), tx2(PAY_LEN, 0x32);
    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    /* 1. Matched directly. */
    uct_cxi_tag_recv_ctx r1;
    init_recv_ctx(r1);
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &r1.super));
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx1.data(), PAY_LEN));
    poll_until(r1.completed);
    EXPECT_EQ(tx1, rx_buf);

    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx2.data(), PAY_LEN));
    poll_until(m_unexp.fired);
    ASSERT_EQ(1u, m_unexp.all.size());
    EXPECT_EQ(tx2, m_unexp.all[0].data)
            << "the message was taken by a receive that had completed";

    /* 2. Cancelled. */
    m_unexp.fired = false;
    m_unexp.all.clear();
    uct_cxi_tag_recv_ctx r2;
    init_recv_ctx(r2);
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &r2.super));
    ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(), &r2.super, 0));
    poll_until(r2.completed);
    EXPECT_EQ(UCS_ERR_CANCELED, r2.status);

    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx2.data(), PAY_LEN));
    poll_until(m_unexp.fired);
    ASSERT_EQ(1u, m_unexp.all.size());
    EXPECT_EQ(tx2, m_unexp.all[0].data)
            << "the message was taken by a receive that was cancelled";

    flush_ep(sender(), ep);
    dereg(receiver(), rx_memh);
}


/* -------------------------------------------------------------------------
 * Software rendezvous request (uct_ep_tag_rndv_request): UCP's RTS sent as a
 * tagged message, handled by the receiver's UCP through rndv_cb
 * -------------------------------------------------------------------------
 */

/** A request of \a len bytes with a pattern \a seed tells apart. */
static std::vector<uint8_t> sw_rts(size_t len, uint8_t seed)
{
    std::vector<uint8_t> rts(len);
    for (size_t i = 0; i < len; i++) {
        rts[i] = static_cast<uint8_t>(seed + i * 7);
    }
    return rts;
}

/** With no receive posted, the request reaches rndv_cb as the unexpected
 * rendezvous it is: no remote address, no key, the RTS as the header, and not
 * as an eager message. */
UCS_TEST_P(test_cxi_tag, sw_rndv_request_unexpected)
{
    static const uct_tag_t TAG = 0xC1A5000000000001ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rts = sw_rts(60, 0x21);
    ASSERT_UCS_OK(uct_ep_tag_rndv_request(ep, TAG, rts.data(), rts.size(), 0));

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    while (m_unexp.rndv_all.empty() && (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_EQ(1u, m_unexp.rndv_all.size());

    const uct_cxi_tag_unexp_rndv &r = m_unexp.rndv_all[0];
    EXPECT_EQ(TAG, r.tag);
    EXPECT_EQ(rts, r.hdr);
    EXPECT_EQ(0u, r.remote_addr);
    EXPECT_EQ(0u, r.length);
    EXPECT_FALSE(r.has_rkey);
    EXPECT_TRUE(m_unexp.all.empty()) << "reported as an eager message";

    flush_ep(sender(), ep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/** Matched by a receive posted before it arrives: the RTS lands in the
 * receive's buffer and reaches the receive's rndv_cb, not completed_cb. */
UCS_TEST_P(test_cxi_tag, sw_rndv_request_direct_match)
{
    static const uct_tag_t TAG = 0xC1A5000000000002ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rts     = sw_rts(60, 0x22);
    std::vector<uint8_t> rx_buf(256, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), rx_buf.size());
    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);
    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = rx_buf.size();
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &rctx.super));

    ASSERT_UCS_OK(uct_ep_tag_rndv_request(ep, TAG, rts.data(), rts.size(), 0));
    poll_until(rctx.rndv_matched);

    EXPECT_FALSE(rctx.completed);
    EXPECT_EQ(UCS_OK, rctx.rndv_status);
    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(rts, std::vector<uint8_t>(rctx.rndv_hdr,
                                        rctx.rndv_hdr + rctx.rndv_hdr_len));
    EXPECT_TRUE(std::equal(rts.begin(), rts.end(), rx_buf.begin()))
            << "the request is not in the receive's buffer";
    EXPECT_TRUE(m_unexp.all.empty() && m_unexp.rndv_all.empty());

    flush_ep(sender(), ep);
    dereg(receiver(), rx_memh);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/** As above, matched by a receive posted after it arrived (a delayed match,
 * copied from the overflow buffer). */
UCS_TEST_P(test_cxi_tag, sw_rndv_request_delayed_match)
{
    static const uct_tag_t TAG = 0xC1A5000000000003ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rts     = sw_rts(60, 0x23);
    std::vector<uint8_t> rx_buf(256, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), rx_buf.size());

    ASSERT_UCS_OK(uct_ep_tag_rndv_request(ep, TAG, rts.data(), rts.size(), 0));
    usleep(200000); /* it is in the overflow list before the receive */

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);
    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = rx_buf.size();
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &rctx.super));
    poll_until(rctx.rndv_matched);

    EXPECT_FALSE(rctx.completed);
    EXPECT_EQ(UCS_OK, rctx.rndv_status);
    EXPECT_EQ(rts, std::vector<uint8_t>(rctx.rndv_hdr,
                                        rctx.rndv_hdr + rctx.rndv_hdr_len));
    EXPECT_TRUE(m_unexp.all.empty() && m_unexp.rndv_all.empty());

    flush_ep(sender(), ep);
    dereg(receiver(), rx_memh);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/** A receive too small for the request is told so, rather than given a cut
 * request as a good one. */
UCS_TEST_P(test_cxi_tag, sw_rndv_request_into_a_small_receive)
{
    static const uct_tag_t TAG = 0xC1A5000000000004ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> rts     = sw_rts(60, 0x24);
    std::vector<uint8_t> rx_buf(32, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), rx_buf.size());
    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);
    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = rx_buf.size();
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &rctx.super));

    ASSERT_UCS_OK(uct_ep_tag_rndv_request(ep, TAG, rts.data(), rts.size(), 0));
    poll_until(rctx.rndv_matched);

    EXPECT_EQ(UCS_ERR_MESSAGE_TRUNCATED, rctx.rndv_status);
    EXPECT_LE(rctx.rndv_hdr_len, rx_buf.size());

    flush_ep(sender(), ep);
    dereg(receiver(), rx_memh);
}

/** The mark of a request is not available to eager messages. */
UCS_TEST_P(test_cxi_tag, sw_rndv_mark_is_refused_for_eager)
{
    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> buf(64, 0x5A);
    uct_mem_h            memh = reg(sender(), buf.data(), buf.size());
    uct_iov_t            iov;
    iov.buffer = buf.data();
    iov.length = buf.size();
    iov.memh   = memh;
    iov.stride = 0;
    iov.count  = 1;

    auto pack = [](void *dst, void *arg) -> size_t {
        memset(dst, 0x5A, 64);
        return 64;
    };
    EXPECT_EQ(static_cast<ssize_t>(UCS_ERR_INVALID_PARAM),
              uct_ep_tag_eager_bcopy(ep, 0x1, UCT_CXI_TAG_SW_RNDV_IMM, +pack,
                                     NULL, 0));
    EXPECT_EQ(UCS_ERR_INVALID_PARAM,
              uct_ep_tag_eager_zcopy(ep, 0x1, UCT_CXI_TAG_SW_RNDV_IMM, &iov, 1,
                                     0, NULL));

    dereg(sender(), memh);
    flush_ep(sender(), ep);
}


/*
 * The ring of posted receives and its fences: a fence follows every
 * TAG_FENCE_INTERVAL posts and moves the ring's tail when it returns; slots and
 * ring positions are recycled over many times the ring's size.
 */
UCS_TEST_P(test_cxi_tag, fences_advance_the_ring)
{
    static const size_t    PAY_LEN = 8;
    static const unsigned  ROUNDS  = 4 * UCT_CXI_TAG_PEND_SIZE;

    uct_cxi_iface_t     *riface = cxi_iface(receiver());
    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
    unsigned             interval = riface->tag.fence_interval;

    ASSERT_GE(interval, 1u);
    ASSERT_LT(interval, UCT_CXI_TAG_PEND_SIZE / 2);

    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    EXPECT_EQ(0u, riface->tag.pend_head);
    for (unsigned i = 0; i < ROUNDS; i++) {
        uct_cxi_tag_recv_ctx rctx;
        init_recv_ctx(rctx);
        ASSERT_EQ(UCS_OK, uct_iface_tag_recv_zcopy(receiver().iface(),
                                                   0xFE0000 + i, UCS_MASK(64),
                                                   &iov, 1, &rctx.super))
                << "round " << i;
        ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                &rctx.super, 1));
        if ((i % interval) == (interval - 1)) {
            /* The fence of these returns once the receiver is looked at. */
            ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
            while (((riface->tag.pend_head - riface->tag.pend_tail) >=
                    interval) && (ucs_get_time() < deadline)) {
                uct_iface_progress(receiver().iface());
            }
            EXPECT_LT(riface->tag.pend_head - riface->tag.pend_tail, interval)
                    << "round " << i << ": no fence returned";
        }
    }

    EXPECT_EQ(ROUNDS, riface->tag.pend_head);
    EXPECT_EQ(riface->tag.fence_head, riface->tag.fence_tail)
            << "a fence is still in flight";
    EXPECT_EQ(ROUNDS / interval, riface->tag.fence_head);

    dereg(receiver(), rx_memh);
}


/*
 * The delayed match of a receive that UCP gave up reaches us before the arrival
 * of the message it took (the order the NIC has been seen to produce): the
 * message is not lost, UCP is told of it. The events are drained by hand and
 * handed to the handlers in that order, since which one the NIC writes first
 * is not for a test to decide.
 */
UCS_TEST_P(test_cxi_tag, match_of_a_cancelled_receive_is_reported)
{
    static const size_t    PAY_LEN = 32;
    static const uct_tag_t TAG     = 0xC1A3000000000001ULL;

    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep     = sender().ep(0);
    uct_cxi_iface_t *riface = cxi_iface(receiver());

    std::vector<uint8_t> tx(PAY_LEN, 0x5A);
    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);

    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx.data(), PAY_LEN));
    usleep(200000);

    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);
    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1, &rctx.super));
    usleep(200000); /* the receive has taken the message in hardware */
    ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(), &rctx.super,
                                            1));

    std::vector<union c_event> events;
    const union c_event       *arrival = NULL, *match = NULL;
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(2.0);
    while (((arrival == NULL) || (match == NULL)) &&
           (ucs_get_time() < deadline)) {
        const union c_event *ev;
        while ((ev = cxi_eq_get_event(riface->rx_eq.evtq)) != NULL) {
            if (ev->tgt_long.ptlte_index == riface->tag.pte->ptn) {
                events.push_back(*ev);
            }
        }
        cxi_eq_ack_events(riface->rx_eq.evtq);

        arrival = match = NULL;
        for (const union c_event &e : events) {
            if ((e.hdr.event_type == C_EVENT_PUT) &&
                (e.tgt_long.ptl_list == C_PTL_LIST_OVERFLOW)) {
                arrival = &e;
            } else if (e.hdr.event_type == C_EVENT_PUT_OVERFLOW) {
                match = &e;
            }
        }
    }
    ASSERT_NE(static_cast<const union c_event *>(NULL), arrival);
    ASSERT_NE(static_cast<const union c_event *>(NULL), match);

    /* The match first, then the arrival. */
    uct_cxi_iface_tag_handle_eager_match(riface, match);
    EXPECT_TRUE(m_unexp.all.empty()) << "reported before it arrived";
    uct_cxi_iface_tag_handle_ovf_arrival(riface, arrival);

    ASSERT_EQ(1u, m_unexp.all.size()) << "the message was lost";
    EXPECT_EQ(TAG, m_unexp.all[0].tag);
    EXPECT_EQ(tx, m_unexp.all[0].data);
    EXPECT_FALSE(rctx.completed) << "a force-cancelled receive completed";
    EXPECT_EQ(0, riface->tag.ovf_refcnt[0]) << "the buffer is still held";

    dereg(receiver(), rx_memh);
}



#ifndef UCT_CXI_DISABLE_FC

/* ------------------------------------------------------------------------
 * Flow control of tag messages: what a send is charged, and what happens to
 * the charge depending on the list the message matched.
 * ------------------------------------------------------------------------
 */

/**
 * Tag sends are charged event slots (two for an eager message, three for a
 * rendezvous one) and buffer space of the tag class (the message's length in
 * units; none for a rendezvous). A message that matches a posted receive is
 * not tracked by the target, and its sender takes the charge back when its ACK
 * says so; one that does not stays charged until the target is done with it.
 */
class test_cxi_tag_credits : public test_cxi_tag_base {
protected:
    enum send_kind {
        SEND_SHORT,
        SEND_BCOPY,
        SEND_ZCOPY,
        SEND_RNDV
    };

    static const size_t   PAY_LEN  = 100;  /* two units */
    static const size_t   RNDV_LEN = 4096;
    static const uint64_t TAG      = 0x5AC0000000000001ULL;

    struct sent_t {
        std::vector<uint8_t>   buf;
        uct_mem_h              memh;
        uct_cxi_rndv_send_ctx  sctx;
        void                  *rop;
    };

    uct_cxi_peer_t *tx_peer()
    {
        return ucs_derived_of(sender().ep(0), uct_cxi_ep_t)->peer;
    }

    /** The record the receiver holds for the sender. */
    uct_cxi_peer_t *rx_peer()
    {
        return cxi_find_peer(receiver(), sender());
    }

    static size_t kind_len(send_kind kind)
    {
        return (kind == SEND_RNDV) ? RNDV_LEN : PAY_LEN;
    }

    static unsigned kind_slots(send_kind kind)
    {
        return (kind == SEND_RNDV) ? UCT_CXI_FC_SLOTS_TAG_RNDV :
                                     UCT_CXI_FC_SLOTS_TAG_EAGER;
    }

    static unsigned kind_units(send_kind kind)
    {
        return (kind == SEND_RNDV) ? 0 : UCT_CXI_FC_UNITS(PAY_LEN);
    }

    /** A rendezvous also sends the endpoint's one announce, an Active
     * Message the target gives back credits for on its own. */
    static unsigned kind_extra_slots(send_kind kind)
    {
        return (kind == SEND_RNDV) ? UCT_CXI_FC_SLOTS_AM : 0;
    }

    /** Send one message of \a kind with tag \a tag. */
    void send_one(send_kind kind, uct_tag_t tag, sent_t &sent,
                  ucs_status_t *status_p = NULL)
    {
        uct_ep_h     ep     = sender().ep(0);
        size_t       len    = kind_len(kind);
        ucs_status_t status = UCS_OK;
        uct_iov_t    iov;

        sent.buf.assign(len, 0x5A);
        sent.memh = UCT_MEM_HANDLE_NULL;
        sent.rop  = NULL;
        init_rndv_send_ctx(sent.sctx);

        if ((kind == SEND_ZCOPY) || (kind == SEND_RNDV)) {
            sent.memh  = reg(sender(), sent.buf.data(), len);
            iov.buffer = sent.buf.data();
            iov.length = len;
            iov.memh   = sent.memh;
            iov.stride = 0;
            iov.count  = 1;
        }

        switch (kind) {
        case SEND_SHORT:
            status = uct_ep_tag_eager_short(ep, tag, sent.buf.data(), len);
            break;
        case SEND_BCOPY: {
            auto pack = [](void *dst, void *arg) -> size_t {
                size_t n = *static_cast<size_t *>(arg);
                memset(dst, 0x5A, n);
                return n;
            };
            ssize_t ret = uct_ep_tag_eager_bcopy(ep, tag, 0, +pack, &len, 0);
            status = (ret < 0) ? static_cast<ucs_status_t>(ret) : UCS_OK;
            break;
        }
        case SEND_ZCOPY:
            status = uct_ep_tag_eager_zcopy(ep, tag, 0, &iov, 1, 0,
                                            &sent.sctx.super);
            if (status == UCS_INPROGRESS) {
                status = UCS_OK;
            }
            break;
        case SEND_RNDV: {
            uct_cxi_rndv_hdr_wire_t hdr;
            hdr.ep_id    = 0x1111111111111111ULL;
            hdr.req_id   = tag;
            hdr.md_index = 1;
            ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, tag, &hdr,
                                                        sizeof(hdr), &iov, 1,
                                                        0, &sent.sctx.super);
            if (UCS_PTR_IS_ERR(sp)) {
                status = UCS_PTR_STATUS(sp);
            } else {
                sent.rop = sp;
            }
            break;
        }
        }

        if (status_p != NULL) {
            *status_p = status;
        } else {
            ASSERT_UCS_OK(status);
        }
    }

    void release(send_kind kind, sent_t &sent)
    {
        if (sent.memh != UCT_MEM_HANDLE_NULL) {
            dereg(sender(), sent.memh);
        }
    }

    /** Progress only the sender until its sends are all acknowledged. */
    void sender_acked()
    {
        uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(),
                                                 uct_cxi_iface_t);
        ucs_time_t       until  = ucs_get_time() + ucs_time_from_sec(5.0);

        while ((siface->tx.outstanding != 0) && (ucs_get_time() < until)) {
            uct_iface_progress(sender().iface());
        }
        ASSERT_EQ(0u, siface->tx.outstanding) << "sends never acknowledged";
    }

    void check_matched_is_given_back(send_kind kind)
    {
        cxi_connect(sender(), 0, receiver());
        uct_cxi_peer_t *tx    = tx_peer();
        const int32_t   slots = tx->tx.avail_slots;
        const int32_t   tag   = tx->tx.avail_units[UCT_CXI_FC_TAG];
        size_t          len   = kind_len(kind);

        std::vector<uint8_t> rx_buf(len, 0);
        uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), len);
        uct_cxi_tag_recv_ctx rctx;
        uct_iov_t            riov;
        sent_t               sent;

        init_recv_ctx(rctx);
        riov.buffer = rx_buf.data();
        riov.length = len;
        riov.memh   = rx_memh;
        riov.stride = 0;
        riov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                               UCS_MASK(64), &riov, 1,
                                               &rctx.super));
        usleep(50000); /* the receive is in place: the message will match it */

        send_one(kind, TAG, sent);
        poll_until(rctx.completed);
        if (kind == SEND_RNDV) {
            poll_until(sent.sctx.fired);
        }
        ASSERT_TRUE(progress_until_acked());

        /* What it was charged is back; only the announce is still out. */
        EXPECT_EQ(slots - (int32_t)kind_extra_slots(kind), tx->tx.avail_slots);
        EXPECT_EQ(tag, tx->tx.avail_units[UCT_CXI_FC_TAG]);
        EXPECT_EQ(kind_extra_slots(kind), tx->tx.used_slots);
        EXPECT_EQ(0u, tx->tx.used_units[UCT_CXI_FC_TAG]);

        /* The target never tracked it. */
        uct_cxi_peer_t *rx = rx_peer();
        ASSERT_NE(nullptr, rx);
        EXPECT_EQ(0u, rx->rx.ret_units[UCT_CXI_FC_TAG]);
        EXPECT_EQ(kind_extra_slots(kind), rx->rx.ret_slots);

        release(kind, sent);
        dereg(receiver(), rx_memh);
    }

    void check_unmatched_stays_charged(send_kind kind)
    {
        cxi_connect(sender(), 0, receiver());
        uct_cxi_peer_t *tx    = tx_peer();
        const int32_t   slots = tx->tx.avail_slots;
        const int32_t   tag   = tx->tx.avail_units[UCT_CXI_FC_TAG];
        sent_t          sent;

        /* Only the sender makes progress: the target does not get to give
         * anything back, whatever it would do. */
        send_one(kind, TAG, sent);
        sender_acked();

        unsigned total = kind_slots(kind) + kind_extra_slots(kind);
        EXPECT_EQ(slots - (int32_t)total, tx->tx.avail_slots);
        EXPECT_EQ(tag - (int32_t)kind_units(kind),
                  tx->tx.avail_units[UCT_CXI_FC_TAG]);
        EXPECT_EQ(total, tx->tx.used_slots);
        EXPECT_EQ(kind_units(kind), tx->tx.used_units[UCT_CXI_FC_TAG]);

        if (kind == SEND_RNDV) {
            ASSERT_UCS_OK(uct_ep_tag_rndv_cancel(sender().ep(0), sent.rop));
        }
        release(kind, sent);
    }

    /** Send the sender what the receiver owes it, in a GRANT. */
    void grant_now()
    {
        uct_cxi_fc_grant_wanted(ucs_derived_of(receiver().iface(),
                                               uct_cxi_iface_t),
                                rx_peer());
    }

    /** Progress both until \a done, or give up. */
    bool progress_until(const std::function<bool()> &done,
                        double timeout_sec = 5.0)
    {
        ucs_time_t until = ucs_get_time() + ucs_time_from_sec(timeout_sec);

        while (!done() && (ucs_get_time() < until)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        return done();
    }

    /** What the receiver gave back for the message of \a kind, and then the
     * sender got in a GRANT, is all that it was charged. */
    void check_given_back(send_kind kind, int32_t slots, int32_t tag)
    {
        uct_cxi_peer_t *tx = tx_peer();
        uct_cxi_peer_t *rx = rx_peer();

        ASSERT_NE(nullptr, rx);
        cxi_expect_conserved(sender(), receiver());
        EXPECT_EQ(kind_slots(kind) + kind_extra_slots(kind), rx->rx.ret_slots);
        EXPECT_EQ(kind_units(kind), rx->rx.ret_units[UCT_CXI_FC_TAG]);

        grant_now();
        ASSERT_TRUE(progress_until([&]() {
            return (tx->tx.avail_slots == slots) &&
                   (tx->tx.avail_units[UCT_CXI_FC_TAG] == tag);
        })) << "the sender's credits did not all come back";
        EXPECT_EQ(0u, tx->tx.used_slots - rx->rx.ret_slots);
    }

    /** A message nothing was waiting for, reported to the receiver's user. */
    void check_unmatched_is_given_back(send_kind kind)
    {
        cxi_connect(sender(), 0, receiver());
        uct_cxi_peer_t *tx    = tx_peer();
        const int32_t   slots = tx->tx.avail_slots;
        const int32_t   tag   = tx->tx.avail_units[UCT_CXI_FC_TAG];
        sent_t          sent;

        send_one(kind, TAG, sent);
        check_given_back(kind, slots, tag);

        if (kind == SEND_RNDV) {
            ASSERT_UCS_OK(uct_ep_tag_rndv_cancel(sender().ep(0), sent.rop));
        }
        release(kind, sent);
    }

    /** A message that landed unexpected and was taken by a receive posted
     * after it. */
    void check_claimed_later_is_given_back(send_kind kind)
    {
        cxi_connect(sender(), 0, receiver());
        uct_cxi_peer_t *tx    = tx_peer();
        const int32_t   slots = tx->tx.avail_slots;
        const int32_t   tag   = tx->tx.avail_units[UCT_CXI_FC_TAG];
        size_t          len   = kind_len(kind);
        sent_t          sent;

        send_one(kind, TAG, sent);
        sender_acked(); /* it is in the target's hands, unseen by its software */

        std::vector<uint8_t> rx_buf(len, 0);
        uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), len);
        uct_cxi_tag_recv_ctx rctx;
        uct_iov_t            riov;

        init_recv_ctx(rctx);
        riov.buffer = rx_buf.data();
        riov.length = len;
        riov.memh   = rx_memh;
        riov.stride = 0;
        riov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                               UCS_MASK(64), &riov, 1,
                                               &rctx.super));
        poll_until(rctx.completed);
        if (kind == SEND_RNDV) {
            poll_until(sent.sctx.fired);
        }

        check_given_back(kind, slots, tag);

        release(kind, sent);
        dereg(receiver(), rx_memh);
    }

    bool progress_until_acked()
    {
        uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(),
                                                 uct_cxi_iface_t);
        ucs_time_t       until  = ucs_get_time() + ucs_time_from_sec(5.0);

        while ((siface->tx.outstanding != 0) && (ucs_get_time() < until)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        return siface->tx.outstanding == 0;
    }
};

UCS_TEST_P(test_cxi_tag_credits, matched_short_is_given_back)
{
    check_matched_is_given_back(SEND_SHORT);
}

UCS_TEST_P(test_cxi_tag_credits, matched_bcopy_is_given_back)
{
    check_matched_is_given_back(SEND_BCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, matched_zcopy_is_given_back)
{
    check_matched_is_given_back(SEND_ZCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, matched_rndv_is_given_back)
{
    check_matched_is_given_back(SEND_RNDV);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_short_stays_charged)
{
    check_unmatched_stays_charged(SEND_SHORT);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_bcopy_stays_charged)
{
    check_unmatched_stays_charged(SEND_BCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_zcopy_stays_charged)
{
    check_unmatched_stays_charged(SEND_ZCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_rndv_stays_charged)
{
    check_unmatched_stays_charged(SEND_RNDV);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_short_is_given_back)
{
    check_unmatched_is_given_back(SEND_SHORT);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_bcopy_is_given_back)
{
    check_unmatched_is_given_back(SEND_BCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_zcopy_is_given_back)
{
    check_unmatched_is_given_back(SEND_ZCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, unmatched_rndv_is_given_back)
{
    check_unmatched_is_given_back(SEND_RNDV);
}

UCS_TEST_P(test_cxi_tag_credits, claimed_later_short_is_given_back)
{
    check_claimed_later_is_given_back(SEND_SHORT);
}

UCS_TEST_P(test_cxi_tag_credits, claimed_later_bcopy_is_given_back)
{
    check_claimed_later_is_given_back(SEND_BCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, claimed_later_zcopy_is_given_back)
{
    check_claimed_later_is_given_back(SEND_ZCOPY);
}

UCS_TEST_P(test_cxi_tag_credits, claimed_later_rndv_is_given_back)
{
    check_claimed_later_is_given_back(SEND_RNDV);
}

/**
 * What a send costs decides whether it can go: with two slots left an eager
 * message goes and a rendezvous one waits; the Active Message pool and the
 * tag pool are separate.
 */
UCS_TEST_P(test_cxi_tag_credits, cost_decides_what_can_go)
{
    cxi_connect(sender(), 0, receiver());
    uct_cxi_peer_t *tx = tx_peer();
    sent_t          sent;
    ucs_status_t    status;

    /* Two slots: the first rendezvous send takes one for its announce, and
     * has too few left for itself, which needs two. */
    tx->tx.avail_slots = UCT_CXI_FC_SLOTS_AM + UCT_CXI_FC_SLOTS_TAG_RNDV - 1;
    send_one(SEND_RNDV, TAG, sent, &status);
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, status) << "a rendezvous needs 2 slots";
    release(SEND_RNDV, sent);
    EXPECT_EQ((int32_t)UCT_CXI_FC_SLOTS_TAG_RNDV - 1, tx->tx.avail_slots);

    /* One slot is enough for an eager message. */
    tx->tx.avail_slots = UCT_CXI_FC_SLOTS_TAG_EAGER;
    send_one(SEND_SHORT, TAG, sent, &status);
    EXPECT_EQ(UCS_OK, status);
    EXPECT_EQ(0, tx->tx.avail_slots);
    release(SEND_SHORT, sent);

    /* Out of tag space but not of slots: an eager waits, an Active Message
     * does not. */
    tx->tx.avail_slots = 10;
    const int32_t tag = tx->tx.avail_units[UCT_CXI_FC_TAG];
    tx->tx.avail_units[UCT_CXI_FC_TAG] = 1;
    send_one(SEND_SHORT, TAG, sent, &status);
    EXPECT_EQ(UCS_ERR_NO_RESOURCE, status) << "100 bytes need 2 units";
    uint64_t payload = 0;
    EXPECT_EQ(UCS_OK, uct_ep_am_short(sender().ep(0), 1, 0, &payload,
                                      sizeof(payload)));
    tx->tx.avail_units[UCT_CXI_FC_TAG] = tag;
    sender_acked();
}

/**
 * Sends that are answered from the priority list do not run a window out, as
 * long as their ACKs come back: a window of three eager messages carries four
 * through, the last waiting in the pending queue for the slots the first ones
 * give back.
 */
class test_cxi_tag_small_window : public test_cxi_tag_credits {
public:
    void init() override
    {
        modify_config("CXI_FC_MSG_WINDOW", "3");
        test_cxi_tag_base::init();
    }
};

struct tag_pending_t {
    uct_pending_req_t super;
    uct_ep_h          ep;
    uct_tag_t         tag;
    const void       *data;
    size_t            len;
    volatile bool     sent;
};

static ucs_status_t tag_pending_cb(uct_pending_req_t *self)
{
    tag_pending_t *req = reinterpret_cast<tag_pending_t *>(self);
    ucs_status_t   status = uct_ep_tag_eager_short(req->ep, req->tag,
                                                   req->data, req->len);

    req->sent = (status == UCS_OK);
    return status;
}

UCS_TEST_P(test_cxi_tag_small_window, matched_sends_flow_through_a_small_window)
{
    static const unsigned N = 4;

    cxi_connect(sender(), 0, receiver());
    uct_cxi_peer_t *tx = tx_peer();
    ASSERT_EQ(3, tx->tx.avail_slots);

    std::vector<uint8_t>  rx_buf[N];
    uct_mem_h             rx_memh[N];
    uct_cxi_tag_recv_ctx  rctx[N];
    std::vector<uint8_t>  data(PAY_LEN, 0x5A);

    for (unsigned i = 0; i < N; i++) {
        rx_buf[i].assign(PAY_LEN, 0);
        rx_memh[i] = reg(receiver(), rx_buf[i].data(), PAY_LEN);
        init_recv_ctx(rctx[i]);

        uct_iov_t iov;
        iov.buffer = rx_buf[i].data();
        iov.length = PAY_LEN;
        iov.memh   = rx_memh[i];
        iov.stride = 0;
        iov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                               UCS_MASK(64), &iov, 1,
                                               &rctx[i].super));
    }
    usleep(50000);

    for (unsigned i = 0; i < 3; i++) {
        ASSERT_UCS_OK(uct_ep_tag_eager_short(sender().ep(0), TAG, data.data(),
                                             PAY_LEN));
    }
    EXPECT_EQ(0, tx->tx.avail_slots);
    EXPECT_EQ(UCS_ERR_NO_RESOURCE,
              uct_ep_tag_eager_short(sender().ep(0), TAG, data.data(),
                                     PAY_LEN));

    tag_pending_t req = {};
    req.super.func = tag_pending_cb;
    req.ep         = sender().ep(0);
    req.tag        = TAG;
    req.data       = data.data();
    req.len        = PAY_LEN;
    ASSERT_UCS_OK(uct_ep_pending_add(sender().ep(0), &req.super, 0));

    poll_until(req.sent);
    for (unsigned i = 0; i < N; i++) {
        poll_until(rctx[i].completed);
        EXPECT_EQ(UCS_OK, rctx[i].status);
        dereg(receiver(), rx_memh[i]);
    }
    ASSERT_TRUE(progress_until_acked());
    EXPECT_EQ(3, tx->tx.avail_slots);
    EXPECT_EQ(0u, tx->tx.used_slots);
}

/**
 * Nothing is waiting for these messages, so they all go to the overflow list,
 * which the target tracks: the window carries three at a time, and the rest
 * wait for the target to give credits back, as GRANTs, for the ones it has
 * reported.
 */
UCS_TEST_P(test_cxi_tag_small_window, unmatched_sends_flow_through_a_small_window)
{
    static const unsigned N = 12;

    cxi_connect(sender(), 0, receiver());
    std::vector<uint8_t> data(PAY_LEN, 0x5A);

    for (unsigned i = 0; i < N; i++) {
        ucs_time_t   until = ucs_get_time() + ucs_time_from_sec(5.0);
        ucs_status_t status;

        /* One send per round: a send is not something to repeat to test it. */
        do {
            status = uct_ep_tag_eager_short(sender().ep(0), TAG, data.data(),
                                            PAY_LEN);
            if (status == UCS_ERR_NO_RESOURCE) {
                uct_iface_progress(sender().iface());
                uct_iface_progress(receiver().iface());
            }
        } while ((status == UCS_ERR_NO_RESOURCE) && (ucs_get_time() < until));
        ASSERT_EQ(UCS_OK, status) << "message " << i
                                  << ": credits never came back";
    }

    ASSERT_TRUE(progress_until([&]() { return m_unexp.all.size() == N; }))
            << m_unexp.all.size() << " of " << N << " reported";
    cxi_expect_conserved(sender(), receiver());
}

/**
 * A tag send that fails is not the target's to give back: it is refunded to
 * the tag pool by its sender.
 */
UCS_TEST_P(test_cxi_tag_credits, failed_send_is_refunded)
{
    cxi_connect(sender(), 0, receiver());
    uct_cxi_peer_t  *tx     = tx_peer();
    uct_cxi_iface_t *riface = ucs_derived_of(receiver().iface(),
                                             uct_cxi_iface_t);
    const int32_t    slots  = tx->tx.avail_slots;
    const int32_t    tag    = tx->tx.avail_units[UCT_CXI_FC_TAG];
    sent_t           sent;

    struct c_set_state_cmd ss = {};
    ss.command.opcode = C_CMD_TGT_SETSTATE;
    ss.ptlte_index    = riface->tag.ptn;
    ss.ptlte_state    = C_PTLTE_DISABLED;
    ASSERT_EQ(UCS_OK, uct_cxi_iface_tgt_post(riface, &ss));
    usleep(100000); /* let the PTE reach the disabled state */

    {
        scoped_log_handler wrap_err(wrap_errors_logger);
        scoped_log_handler wrap_warn(wrap_warns_logger);

        send_one(SEND_SHORT, TAG, sent);
        EXPECT_EQ(slots - (int32_t)UCT_CXI_FC_SLOTS_TAG_EAGER,
                  tx->tx.avail_slots) << "charged when sent";
        ASSERT_TRUE(progress_until_acked());

        /* Let the receiver finish re-enabling its PTE while still wrapped. */
        ucs_time_t until = ucs_get_time() + ucs_time_from_sec(0.5);
        while (ucs_get_time() < until) {
            uct_iface_progress(receiver().iface());
        }
    }

    EXPECT_EQ(slots, tx->tx.avail_slots)
            << "a send that never arrived must give its credits back";
    EXPECT_EQ(tag, tx->tx.avail_units[UCT_CXI_FC_TAG]);
    EXPECT_EQ(0u, tx->tx.used_slots);
    EXPECT_EQ(0u, tx->tx.used_units[UCT_CXI_FC_TAG]);
    release(SEND_SHORT, sent);
}

#endif /* UCT_CXI_DISABLE_FC */

_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag, cxi)
#ifndef UCT_CXI_DISABLE_FC
_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_credits, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_small_window, cxi)
#endif
