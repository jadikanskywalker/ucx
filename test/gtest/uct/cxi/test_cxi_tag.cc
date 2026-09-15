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

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <cstring>
#include <vector>
#include <unistd.h>


class test_cxi_tag : public test_cxi_tag_base {};


/* -------------------------------------------------------------------------
 * Direct match: priority LE already posted before the message arrives
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag, direct_match_short)
{
    static const uct_tag_t TAG     = 0x1122334455667788ULL;
    static const size_t    PAY_LEN = 64;
    static const uint8_t   FILL    = 0xA5;

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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

    sender().connect_to_iface(0, receiver());
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


_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag, cxi)
