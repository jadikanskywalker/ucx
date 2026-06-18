/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Active Message unit tests — ep_am_short, ep_am_bcopy.
 *
 * Wire format recap
 * ─────────────────
 * am_short: data in OVERFLOW rx_buf = [uint64_t header (8 B)][payload bytes].
 *   The handler receives the full concatenated buffer (length = 8 + payload).
 *
 * am_bcopy: data in OVERFLOW rx_buf = raw output of pack_cb (no implicit hdr).
 *   The handler receives whatever the pack_cb wrote (length = packed bytes).
 *
 * Both am_short and am_bcopy generate C_EVENT_ACK on the sender (TX) and
 * C_EVENT_PUT on the receiver (RX/AM OVERFLOW LE).  We poll both ifaces until
 * the handler fires.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_am.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <cstring>
#include <vector>


/* -------------------------------------------------------------------------
 * Fixture
 * -------------------------------------------------------------------------
 */

class test_cxi_am : public test_cxi_am_base {};


/* -------------------------------------------------------------------------
 * ep_am_short tests
 * -------------------------------------------------------------------------
 */

/**
 * Send a single am_short with a 64-byte payload.
 *
 * Wire data: [header(8B)][payload(64B)] = 72 bytes total.
 * Verify the handler receives the correct header and payload.
 */
UCS_TEST_P(test_cxi_am, am_short_single)
{
    static const uint8_t  AM_ID    = 1;
    static const uint64_t HEADER   = 0xDEADBEEF12345678ULL;
    static const size_t   PAY_LEN  = 64;
    static const uint8_t  PAY_FILL = 0xA0;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uint8_t payload[PAY_LEN];
    memset(payload, PAY_FILL, PAY_LEN);

    ASSERT_UCS_OK(uct_ep_am_short(ep, AM_ID, HEADER, payload, PAY_LEN));

    poll_am(ep, ctx);

    /* Verify total length: 8-byte header + payload */
    ASSERT_EQ(sizeof(uint64_t) + PAY_LEN, ctx.data.size());

    uint64_t recv_hdr = 0;
    memcpy(&recv_hdr, ctx.data.data(), sizeof(uint64_t));
    EXPECT_EQ(HEADER, recv_hdr) << "AM header mismatch";

    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(PAY_FILL, ctx.data[sizeof(uint64_t) + i])
                << "payload byte " << i << " mismatch";
    }
}

/**
 * Send am_short at the maximum payload size (184 B = C_MAX_IDC_PAYLOAD_UNR - 8).
 * Verify that the transport accepts it and delivers all bytes correctly.
 */
UCS_TEST_P(test_cxi_am, am_short_max)
{
    static const uint8_t  AM_ID   = 2;
    static const uint64_t HEADER  = 0xCAFEBABE00000001ULL;
    /* C_MAX_IDC_PAYLOAD_UNR = 192; minus 8-byte header = 184 */
    static const size_t   PAY_LEN = C_MAX_IDC_PAYLOAD_UNR - sizeof(uint64_t);

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> payload(PAY_LEN);
    for (size_t i = 0; i < PAY_LEN; i++) {
        payload[i] = static_cast<uint8_t>(i & 0xff);
    }

    ASSERT_UCS_OK(uct_ep_am_short(ep, AM_ID, HEADER, payload.data(), PAY_LEN));

    poll_am(ep, ctx);

    ASSERT_EQ(sizeof(uint64_t) + PAY_LEN, ctx.data.size());

    uint64_t recv_hdr = 0;
    memcpy(&recv_hdr, ctx.data.data(), sizeof(uint64_t));
    EXPECT_EQ(HEADER, recv_hdr);
    EXPECT_EQ(0, memcmp(ctx.data.data() + sizeof(uint64_t),
                        payload.data(), PAY_LEN))
            << "max-payload content mismatch";
}

/**
 * Send multiple am_short messages back-to-back on the same EP.
 * Each uses a distinct AM ID, header, and payload pattern.
 * Verifies that the OVERFLOW buffer accumulates multiple messages correctly.
 */
UCS_TEST_P(test_cxi_am, am_short_multiple)
{
    static const size_t  N       = 4;
    static const size_t  PAY_LEN = 32;

    /* One context per AM ID. */
    uct_cxi_am_recv_ctx ctx[N];
    for (size_t i = 0; i < N; i++) {
        ctx[i].fired = false;
        set_am_handler(static_cast<uint8_t>(i + 1), &ctx[i]);
    }

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    for (size_t i = 0; i < N; i++) {
        uint64_t hdr      = static_cast<uint64_t>(0x1000 + i);
        uint8_t  payload[PAY_LEN];
        memset(payload, static_cast<int>(0xB0 + i), PAY_LEN);

        ASSERT_UCS_OK(uct_ep_am_short(ep, static_cast<uint8_t>(i + 1),
                                      hdr, payload, PAY_LEN));
    }

    /* Poll until all handlers have fired. */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    bool all_fired = false;
    while (!all_fired && ucs_get_time() < deadline) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
        all_fired = true;
        for (size_t i = 0; i < N; i++) {
            if (!ctx[i].fired) {
                all_fired = false;
                break;
            }
        }
    }
    ASSERT_TRUE(all_fired) << "Not all AM handlers fired within 5 s";

    for (size_t i = 0; i < N; i++) {
        ASSERT_EQ(sizeof(uint64_t) + PAY_LEN, ctx[i].data.size())
                << "handler " << i << " data size wrong";

        uint64_t recv_hdr = 0;
        memcpy(&recv_hdr, ctx[i].data.data(), sizeof(uint64_t));
        EXPECT_EQ(static_cast<uint64_t>(0x1000 + i), recv_hdr)
                << "handler " << i << " header mismatch";

        uint8_t expected_fill = static_cast<uint8_t>(0xB0 + i);
        for (size_t j = 0; j < PAY_LEN; j++) {
            EXPECT_EQ(expected_fill, ctx[i].data[sizeof(uint64_t) + j])
                    << "handler " << i << " payload byte " << j;
        }
    }
}


/* -------------------------------------------------------------------------
 * ep_am_bcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Send a single am_bcopy with a 512-byte payload.
 * The pack_cb writes a known pattern; the handler verifies it.
 */
UCS_TEST_P(test_cxi_am, am_bcopy_single)
{
    static const uint8_t  AM_ID    = 5;
    static const size_t   PAY_LEN  = 512;
    static const uint8_t  PAY_FILL = 0xC3;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Pack a known pattern into the desc buffer. */
    struct { uint8_t fill; size_t len; } arg = {PAY_FILL, PAY_LEN};
    auto pack = [](void *dst, void *a) -> size_t {
        auto *p = static_cast<decltype(arg) *>(a);
        memset(dst, p->fill, p->len);
        return p->len;
    };

    ssize_t ret = uct_ep_am_bcopy(ep, AM_ID, +pack, &arg, 0);
    ASSERT_EQ(static_cast<ssize_t>(PAY_LEN), ret);

    poll_am(ep, ctx);

    ASSERT_EQ(PAY_LEN, ctx.data.size());
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(PAY_FILL, ctx.data[i]) << "bcopy byte " << i << " mismatch";
    }
}

/**
 * Send multiple am_bcopy messages with distinct per-message patterns.
 * Verifies that successive bcopy messages are independently delivered.
 */
UCS_TEST_P(test_cxi_am, am_bcopy_multiple)
{
    static const size_t  N       = 4;
    static const size_t  PAY_LEN = 256;

    uct_cxi_am_recv_ctx ctx[N];
    for (size_t i = 0; i < N; i++) {
        ctx[i].fired = false;
        set_am_handler(static_cast<uint8_t>(10 + i), &ctx[i]);
    }

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    for (size_t i = 0; i < N; i++) {
        struct { uint8_t fill; size_t len; } arg = {
            static_cast<uint8_t>(0xD0 + i), PAY_LEN
        };
        auto pack = [](void *dst, void *a) -> size_t {
            auto *p = static_cast<decltype(arg) *>(a);
            memset(dst, p->fill, p->len);
            return p->len;
        };

        ssize_t ret = uct_ep_am_bcopy(ep, static_cast<uint8_t>(10 + i),
                                      +pack, &arg, 0);
        ASSERT_EQ(static_cast<ssize_t>(PAY_LEN), ret)
                << "bcopy " << i << " pack returned wrong length";
    }

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    bool all_fired = false;
    while (!all_fired && ucs_get_time() < deadline) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
        all_fired = true;
        for (size_t i = 0; i < N; i++) {
            if (!ctx[i].fired) {
                all_fired = false;
                break;
            }
        }
    }
    ASSERT_TRUE(all_fired) << "Not all bcopy AM handlers fired within 5 s";

    /* Drain sender C_EVENT_SEND completions so descs are returned to the pool
     * before fixture teardown (C_EVENT_SEND is the AM bcopy completion). */
    ucs_status_t flush_st;
    do {
        uct_iface_progress(sender().iface());
        flush_st = uct_ep_flush(ep, 0, NULL);
    } while (flush_st == UCS_INPROGRESS && ucs_get_time() < deadline);

    for (size_t i = 0; i < N; i++) {
        ASSERT_EQ(PAY_LEN, ctx[i].data.size())
                << "bcopy handler " << i << " wrong data size";
        uint8_t expected = static_cast<uint8_t>(0xD0 + i);
        for (size_t j = 0; j < PAY_LEN; j++) {
            EXPECT_EQ(expected, ctx[i].data[j])
                    << "bcopy handler " << i << " byte " << j;
        }
    }
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_am, cxi)
