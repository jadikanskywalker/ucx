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

#include <uct/cxi/base/cxi_ep.h>
#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <cstring>
#include <unistd.h>
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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


/* -------------------------------------------------------------------------
 * ep_am_zcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Send a single am_zcopy with an 8-byte header + 4096-byte payload.
 * Header and payload are contiguous (same registered buffer) — tests
 * the fast path (single DMA from header pointer).
 */
UCS_TEST_P(test_cxi_am, am_zcopy_single)
{
    static const uint8_t  AM_ID    = 20;
    static const uint64_t HEADER   = 0xABCD1234DEAD5678ULL;
    static const size_t   HDR_LEN  = sizeof(uint64_t);
    static const size_t   PAY_LEN  = 4096;
    static const uint8_t  PAY_FILL = 0xE7;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Contiguous: [header(8B)][payload(4096B)] in one registered buffer. */
    std::vector<uint8_t> buf(HDR_LEN + PAY_LEN);
    memcpy(buf.data(), &HEADER, HDR_LEN);
    memset(buf.data() + HDR_LEN, PAY_FILL, PAY_LEN);
    uct_mem_h memh = reg(sender(), buf.data(), buf.size());

    uct_iov_t iov;
    iov.buffer = buf.data() + HDR_LEN;
    iov.length = PAY_LEN;
    iov.memh   = memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t st = uct_ep_am_zcopy(ep, AM_ID, buf.data(), HDR_LEN,
                                       &iov, 1, 0, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);

    poll_am(ep, ctx);

    ASSERT_EQ(HDR_LEN + PAY_LEN, ctx.data.size());
    uint64_t recv_hdr = 0;
    memcpy(&recv_hdr, ctx.data.data(), HDR_LEN);
    EXPECT_EQ(HEADER, recv_hdr) << "zcopy header mismatch";
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(PAY_FILL, ctx.data[HDR_LEN + i])
                << "zcopy byte " << i << " mismatch";
    }

    dereg(sender(), memh);
}

/**
 * Send multiple am_zcopy messages with 8-byte headers + distinct payloads.
 * Header and payload are contiguous per message (fast path).
 */
UCS_TEST_P(test_cxi_am, am_zcopy_multiple)
{
    static const size_t  N       = 4;
    static const size_t  HDR_LEN = sizeof(uint64_t);
    static const size_t  PAY_LEN = 1024;

    uct_cxi_am_recv_ctx ctx[N];
    for (size_t i = 0; i < N; i++) {
        ctx[i].fired = false;
        set_am_handler(static_cast<uint8_t>(21 + i), &ctx[i]);
    }

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> bufs[N];
    uct_mem_h memhs[N];
    for (size_t i = 0; i < N; i++) {
        bufs[i].resize(HDR_LEN + PAY_LEN);
        uint64_t hdr = static_cast<uint64_t>(0x2000 + i);
        memcpy(bufs[i].data(), &hdr, HDR_LEN);
        memset(bufs[i].data() + HDR_LEN, static_cast<int>(0xF0 + i), PAY_LEN);
        memhs[i] = reg(sender(), bufs[i].data(), bufs[i].size());
    }

    for (size_t i = 0; i < N; i++) {
        uct_iov_t iov;
        iov.buffer = bufs[i].data() + HDR_LEN;
        iov.length = PAY_LEN;
        iov.memh   = memhs[i];
        iov.stride = 0;
        iov.count  = 1;

        ucs_status_t st = uct_ep_am_zcopy(ep,
                                           static_cast<uint8_t>(21 + i),
                                           bufs[i].data(), HDR_LEN,
                                           &iov, 1, 0, NULL);
        ASSERT_EQ(UCS_INPROGRESS, st) << "zcopy " << i << " failed";
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
    ASSERT_TRUE(all_fired) << "Not all zcopy AM handlers fired within 5 s";

    /* Drain sender completions. */
    ucs_status_t flush_st;
    do {
        uct_iface_progress(sender().iface());
        flush_st = uct_ep_flush(ep, 0, NULL);
    } while (flush_st == UCS_INPROGRESS && ucs_get_time() < deadline);

    for (size_t i = 0; i < N; i++) {
        ASSERT_EQ(HDR_LEN + PAY_LEN, ctx[i].data.size())
                << "zcopy handler " << i << " wrong data size";
        uint64_t recv_hdr = 0;
        memcpy(&recv_hdr, ctx[i].data.data(), HDR_LEN);
        EXPECT_EQ(static_cast<uint64_t>(0x2000 + i), recv_hdr)
                << "zcopy handler " << i << " header mismatch";
        uint8_t expected = static_cast<uint8_t>(0xF0 + i);
        for (size_t j = 0; j < PAY_LEN; j++) {
            EXPECT_EQ(expected, ctx[i].data[HDR_LEN + j])
                    << "zcopy handler " << i << " byte " << j;
        }
        dereg(sender(), memhs[i]);
    }
}


/**
 * Send am_zcopy with a non-contiguous header (stack variable) and registered
 * IOV payload.  Exercises the header_data fallback path: header is packed into
 * cmd.header_data, UCT_CXI_AM_HDR_FLAG is set, and the receiver prepends
 * header_data before the payload in the ME buffer.
 */
UCS_TEST_P(test_cxi_am, am_zcopy_noncontiguous_header)
{
    static const uint8_t  AM_ID    = 25;
    static const size_t   PAY_LEN  = 2048;
    static const uint8_t  PAY_FILL = 0xBB;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Header on the stack — deliberately NOT in the registered IOV region. */
    uint64_t hdr = 0xFEEDFACE99887766ULL;

    /* Payload in a separate registered buffer. */
    std::vector<uint8_t> payload(PAY_LEN, PAY_FILL);
    uct_mem_h memh = reg(sender(), payload.data(), PAY_LEN);

    uct_iov_t iov;
    iov.buffer = payload.data();
    iov.length = PAY_LEN;
    iov.memh   = memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t st = uct_ep_am_zcopy(ep, AM_ID, &hdr, sizeof(hdr),
                                       &iov, 1, 0, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);

    poll_am(ep, ctx);

    /* Handler should see [header(8B)][payload(2048B)]. */
    ASSERT_EQ(sizeof(uint64_t) + PAY_LEN, ctx.data.size());

    uint64_t recv_hdr = 0;
    memcpy(&recv_hdr, ctx.data.data(), sizeof(uint64_t));
    EXPECT_EQ(hdr, recv_hdr) << "non-contiguous zcopy header mismatch";

    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(PAY_FILL, ctx.data[sizeof(uint64_t) + i])
                << "non-contiguous zcopy byte " << i << " mismatch";
    }

    dereg(sender(), memh);
}


/**
 * Event routing across the TX and RX event queues.
 *
 * An am_bcopy produces an ACK for the sender's command (TX queue) and a PUT
 * on the receiver's AM portal (RX queue). Both ifaces are drained through
 * the raw queues, without uct_iface_progress() -- which polls both queues
 * and would hide a misrouted event -- to check that each event lands on the
 * queue it belongs to and none on the other.
 */
UCS_TEST_P(test_cxi_am, eq_split_routing)
{
    static const uint8_t AM_ID = 6;
    static const size_t  LEN   = 64;

    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);
    uct_cxi_iface_t *riface = ucs_derived_of(receiver().iface(), uct_cxi_iface_t);

    ASSERT_NE(siface->tx_eq.evtq->eqn, siface->rx_eq.evtq->eqn)
            << "TX and RX must be distinct hardware queues";

    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

#ifndef UCT_CXI_DISABLE_FC
    /* Connecting is a conversation: the receiver answers the connection
     * request, and the completion of that answer is a TX event on its side.
     * Let it be consumed, so that what is left on the queues is this test's. */
    ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.2);
    while (ucs_get_time() < settle) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
#endif

    auto pack = [](void *dst, void *) -> size_t {
        memset(dst, 0x77, LEN);
        return LEN;
    };
    ASSERT_EQ(static_cast<ssize_t>(LEN),
              uct_ep_am_bcopy(ep, AM_ID, +pack, NULL, 0));

    /* The message must show up as a PUT on the receiver's RX queue. */
    bool        got_put  = false;
    ucs_time_t  deadline = ucs_get_time() + ucs_time_from_sec(2.0);
    while (!got_put && (ucs_get_time() < deadline)) {
        const union c_event *ev;
        while ((ev = cxi_eq_get_event(riface->rx_eq.evtq)) != NULL) {
            got_put |= (ev->hdr.event_type == C_EVENT_PUT);
        }
        cxi_eq_ack_events(riface->rx_eq.evtq);
    }
    EXPECT_TRUE(got_put) << "AM PUT never arrived on the receiver's RX queue";
    EXPECT_EQ(NULL, cxi_eq_get_event(riface->tx_eq.evtq))
            << "the receiver issued nothing, its TX queue must stay empty";

    /* The ACK must be on the sender's TX queue, never its RX queue. The PUT
     * having landed means the ACK is in flight; give it time to arrive. */
    usleep(100000);
    EXPECT_EQ(NULL, cxi_eq_get_event(siface->rx_eq.evtq))
            << "an initiator completion landed on the RX queue";

    /* The normal path must still complete the op from the TX queue. */
    flush_ep(sender(), ep);
}

/**
 * All 64 bits of an AM's match_bits reach the receiver.
 *
 * The AM list entry wildcards every match bit, and the transport itself only
 * uses bits 0-6 (am_id, header flag, announce flag). Bits 7-63 are meant to
 * carry other per-message information (flow control credits piggybacked on
 * ordinary AMs), which only works if they are delivered verbatim, so check it
 * with a distinct pattern in each byte. The message is sent as raw IDC and the
 * receiver's queue read directly, so no handler runs and nothing is
 * interpreted on the way.
 */
UCS_TEST_P(test_cxi_am, match_bits_high_bits_delivered)
{
    static const uint64_t HIGH_PATTERN = 0xA5C3965A3CE1D2B4ULL & ~0x7fULL;
    static const uint64_t MATCH_BITS   = HIGH_PATTERN | 0x03 /* am_id */;

    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);
    uct_cxi_iface_t *riface = ucs_derived_of(receiver().iface(), uct_cxi_iface_t);

    cxi_connect(sender(), 0, receiver());
    uct_cxi_ep_t *cep = ucs_derived_of(sender().ep(0), uct_cxi_ep_t);

    uint64_t payload = 0x1122334455667788ULL;
    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 0;
        cstate.index_ext           = cep->dfa_am_idx_ext;
        ASSERT_EQ(0, cxi_cq_emit_c_state(siface->tx.cmdq, &cstate));
    }
    {
        struct c_idc_msg_hdr hdr = {};
        hdr.dfa        = cep->dfa_am;
        hdr.match_bits = MATCH_BITS;
        ASSERT_EQ(0, cxi_cq_emit_idc_msg(siface->tx.cmdq, &hdr, &payload,
                                         sizeof(payload)));
    }
    cxi_cq_ring(siface->tx.cmdq);

    bool       got      = false;
    uint64_t   received = 0;
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    while (!got && (ucs_get_time() < deadline)) {
        const union c_event *ev;
        while ((ev = cxi_eq_get_event(riface->rx_eq.evtq)) != NULL) {
            if ((ev->hdr.event_type == C_EVENT_PUT) &&
                (ev->tgt_long.ptlte_index == riface->am.pte->ptn)) {
                received = ev->tgt_long.match_bits;
                got      = true;
            }
        }
        cxi_eq_ack_events(riface->rx_eq.evtq);
    }

    ASSERT_TRUE(got) << "AM never arrived";
    EXPECT_EQ(MATCH_BITS, received)
            << "match_bits altered in transit (bits 7-63 must survive)";
}

#ifndef UCT_CXI_DISABLE_FC

/**
 * An am_short is tracked until its ACK, like every other send.
 *
 * IDC shorts used to be fire-and-forget, so a dropped one was invisible and
 * flush did not cover them. They now complete on the TX queue: the ep and iface
 * count them as outstanding from the send until the ACK is processed, which
 * ep_flush waits for.
 */
UCS_TEST_P(test_cxi_am, am_short_tracked_until_ack)
{
    static const uint8_t AM_ID = 7;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    cxi_connect(sender(), 0, receiver());
    uct_ep_h         ep     = sender().ep(0);
    uct_cxi_ep_t    *cep    = ucs_derived_of(ep, uct_cxi_ep_t);
    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);

    uint8_t payload[16] = {};
    ASSERT_UCS_OK(uct_ep_am_short(ep, AM_ID, 0x1234, payload, sizeof(payload)));

    /* Nothing has been progressed yet: the ACK cannot have been handled. */
    EXPECT_EQ(1u, cep->outstanding);
    EXPECT_EQ(1u, siface->tx.outstanding);
    EXPECT_EQ(UCS_INPROGRESS, uct_ep_flush(ep, 0, NULL));

    flush_ep(sender(), ep);
    EXPECT_EQ(0u, cep->outstanding);
    EXPECT_EQ(0u, siface->tx.outstanding);

    poll_am(ep, ctx);
}

/**
 * An ep destroyed while sends are in flight is not freed under them.
 *
 * A send's completion finds its ep through a pointer stored in the command,
 * so freeing the ep at uct_ep_destroy() would leave that completion a dangling
 * one. The ep is kept (flagged destroyed, remembered in the iface) and freed
 * by the last completion, which also forgets it. Nothing here can see the free
 * itself; it is the clean run (and a valgrind run, where available) that shows
 * the completion did not touch freed memory.
 */
UCS_TEST_P(test_cxi_am, ep_destroy_with_am_short_in_flight)
{
    static const uint8_t AM_ID = 8;

    uct_cxi_am_recv_ctx ctx = {false, {}};
    set_am_handler(AM_ID, &ctx);

    cxi_connect(sender(), 0, receiver());
    uct_cxi_ep_t    *cep    = ucs_derived_of(sender().ep(0), uct_cxi_ep_t);
    uct_cxi_iface_t *siface = ucs_derived_of(sender().iface(), uct_cxi_iface_t);

    uint8_t payload[16] = {};
    ASSERT_UCS_OK(uct_ep_am_short(sender().ep(0), AM_ID, 0x1234, payload,
                                  sizeof(payload)));
    ASSERT_EQ(1u, siface->tx.outstanding);

    sender().destroy_ep(0);
    EXPECT_EQ(1u, cep->destroyed) << "the ep must outlive its in-flight send";
    EXPECT_EQ(1u, kh_size(&siface->tx.zombie_eps))
            << "the iface must remember it, to free it if it closes first";

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    while ((siface->tx.outstanding > 0) && (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_EQ(0u, siface->tx.outstanding);
    EXPECT_EQ(0u, kh_size(&siface->tx.zombie_eps))
            << "the last completion must have freed the ep";
}

#endif /* UCT_CXI_DISABLE_FC */


/* -------------------------------------------------------------------------
 * Receive ring wrap-around
 * -------------------------------------------------------------------------
 */

/**
 * A small receive ring (four 64 KiB buffers), so that a few thousand messages
 * of up to the maximum size go round it many times.
 */
class test_cxi_am_small_ring : public test_cxi_am {
protected:
    void init() override
    {
        modify_config("CXI_AM_RX_BUF_SIZE", "64k");
        modify_config("CXI_AM_RX_NUM_BUFS", "4");
#ifndef UCT_CXI_DISABLE_FC
        /* One sender at a time, and no more bytes outstanding than the ring
         * is meant to hold. */
        modify_config("CXI_FC_ACTIVE_SENDERS", "1");
        modify_config("CXI_FC_BYTE_WINDOW", "64k");
#endif
        test_cxi_am::init();
    }
};

struct ring_wrap_rx_t {
    unsigned received[3];
    unsigned bad;
};

enum { RING_WRAP_SHORT, RING_WRAP_BCOPY, RING_WRAP_ZCOPY };

static const size_t RING_WRAP_MAX = 8192;

/* Payload lengths are a function of the sequence number, so that the receiver
 * knows what to expect. */
static inline size_t ring_wrap_short_len(unsigned seq)
{
    return (seq * 13) % 177;
}

static inline size_t ring_wrap_bcopy_len(unsigned seq)
{
    return 1 + (seq * 977) % (RING_WRAP_MAX - sizeof(uint64_t) - 1);
}

static inline size_t ring_wrap_zcopy_len(unsigned seq)
{
    return 1 + (seq * 1531) % RING_WRAP_MAX;
}

static inline uint8_t ring_wrap_zcopy_byte(size_t k)
{
    return (uint8_t)(k * 7 + 3);
}

/* am_short and am_bcopy messages are [seq (8 bytes)][payload], payload byte k
 * being seq + k. */
static void ring_wrap_check_seq(ring_wrap_rx_t *rx, const void *data,
                                size_t length, size_t (*payload_len)(unsigned))
{
    const uint8_t *p   = static_cast<const uint8_t*>(data);
    uint64_t       seq = 0;

    if (length < sizeof(seq)) {
        rx->bad++;
        return;
    }

    memcpy(&seq, p, sizeof(seq));
    if (length != sizeof(seq) + payload_len(seq)) {
        rx->bad++;
        return;
    }

    for (size_t k = 0; k < length - sizeof(seq); k++) {
        if (p[sizeof(seq) + k] != (uint8_t)(seq + k)) {
            rx->bad++;
            return;
        }
    }
}

static size_t (*const ring_wrap_short_len_fn)(unsigned) = ring_wrap_short_len;
static size_t (*const ring_wrap_bcopy_len_fn)(unsigned) = ring_wrap_bcopy_len;

static ucs_status_t ring_wrap_short_handler(void *arg, void *data,
                                            size_t length, unsigned flags)
{
    ring_wrap_rx_t *rx = static_cast<ring_wrap_rx_t*>(arg);

    rx->received[RING_WRAP_SHORT]++;
    ring_wrap_check_seq(rx, data, length, ring_wrap_short_len_fn);
    return UCS_OK;
}

static ucs_status_t ring_wrap_bcopy_handler(void *arg, void *data,
                                            size_t length, unsigned flags)
{
    ring_wrap_rx_t *rx = static_cast<ring_wrap_rx_t*>(arg);

    rx->received[RING_WRAP_BCOPY]++;
    ring_wrap_check_seq(rx, data, length, ring_wrap_bcopy_len_fn);
    return UCS_OK;
}

/* am_zcopy messages are payload only, byte k being a function of k. */
static ucs_status_t ring_wrap_zcopy_handler(void *arg, void *data,
                                            size_t length, unsigned flags)
{
    ring_wrap_rx_t *rx = static_cast<ring_wrap_rx_t*>(arg);
    const uint8_t  *p  = static_cast<const uint8_t*>(data);

    rx->received[RING_WRAP_ZCOPY]++;
    if ((length == 0) || (length > RING_WRAP_MAX)) {
        rx->bad++;
        return UCS_OK;
    }

    for (size_t k = 0; k < length; k++) {
        if (p[k] != ring_wrap_zcopy_byte(k)) {
            rx->bad++;
            return UCS_OK;
        }
    }
    return UCS_OK;
}

struct ring_wrap_pack_t {
    uint64_t seq;
    size_t   payload_len;
};

static size_t ring_wrap_pack(void *dest, void *arg)
{
    const ring_wrap_pack_t *a = static_cast<const ring_wrap_pack_t*>(arg);
    uint8_t                *p = static_cast<uint8_t*>(dest);

    memcpy(p, &a->seq, sizeof(a->seq));
    for (size_t k = 0; k < a->payload_len; k++) {
        p[sizeof(a->seq) + k] = (uint8_t)(a->seq + k);
    }
    return sizeof(a->seq) + a->payload_len;
}

/**
 * Send enough messages, of every kind and of sizes up to the maximum, to go
 * round the receive ring many times, and check that every one arrives intact.
 *
 * The NIC retires a buffer once less than a maximum-size message is left in
 * it, and the next goes into the following one. A buffer retired too late
 * would be left holding a message that does not fit: that one is lost (the
 * sender and the receiver both report the failure, which fails this test).
 */
UCS_TEST_P(test_cxi_am_small_ring, ring_wraps)
{
    static const unsigned PER_KIND = 1000;
    ring_wrap_rx_t        rx       = {{0, 0, 0}, 0};
    unsigned              sent[3]  = {0, 0, 0};

    ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), 1,
                                           ring_wrap_short_handler, &rx, 0));
    ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), 2,
                                           ring_wrap_bcopy_handler, &rx, 0));
    ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), 3,
                                           ring_wrap_zcopy_handler, &rx, 0));
    cxi_connect(sender(), 0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> zbuf(RING_WRAP_MAX);
    for (size_t k = 0; k < zbuf.size(); k++) {
        zbuf[k] = ring_wrap_zcopy_byte(k);
    }
    uct_mem_h memh = reg(sender(), zbuf.data(), zbuf.size());

    std::vector<uint8_t> shortbuf(256);
    ucs_time_t           deadline = ucs_get_time() + ucs_time_from_sec(60.0);
    unsigned             i;

    for (i = 0; (i < 3 * PER_KIND) && (ucs_get_time() < deadline);) {
        unsigned     kind = i % 3;
        unsigned     seq  = i / 3;
        ucs_status_t st;

        if (kind == RING_WRAP_SHORT) {
            size_t len = ring_wrap_short_len(seq);

            for (size_t k = 0; k < len; k++) {
                shortbuf[k] = (uint8_t)(seq + k);
            }
            st = uct_ep_am_short(ep, 1, seq, shortbuf.data(), len);
        } else if (kind == RING_WRAP_BCOPY) {
            ring_wrap_pack_t arg = {seq, ring_wrap_bcopy_len(seq)};
            ssize_t          res = uct_ep_am_bcopy(ep, 2, ring_wrap_pack, &arg,
                                                   0);

            st = (res >= 0) ? UCS_OK : (ucs_status_t)res;
        } else {
            uct_iov_t iov = {zbuf.data(), ring_wrap_zcopy_len(seq), memh, 0, 1};

            st = uct_ep_am_zcopy(ep, 3, NULL, 0, &iov, 1, 0, NULL);
            if (st == UCS_INPROGRESS) {
                st = UCS_OK;
            }
        }

        if (st == UCS_OK) {
            sent[kind]++;
            i++;
        } else {
            ASSERT_EQ(UCS_ERR_NO_RESOURCE, st);
        }

        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_EQ(3 * PER_KIND, i) << "could not send everything in time";

    auto all_in = [&]() {
        return (rx.received[RING_WRAP_SHORT] == sent[RING_WRAP_SHORT]) &&
               (rx.received[RING_WRAP_BCOPY] == sent[RING_WRAP_BCOPY]) &&
               (rx.received[RING_WRAP_ZCOPY] == sent[RING_WRAP_ZCOPY]);
    };
    ucs_time_t until = ucs_get_time() + ucs_time_from_sec(30.0);
    while (!all_in() && (ucs_get_time() < until)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_TRUE(all_in())
            << "short " << rx.received[RING_WRAP_SHORT] << "/"
            << sent[RING_WRAP_SHORT] << " bcopy "
            << rx.received[RING_WRAP_BCOPY] << "/" << sent[RING_WRAP_BCOPY]
            << " zcopy " << rx.received[RING_WRAP_ZCOPY] << "/"
            << sent[RING_WRAP_ZCOPY];
    EXPECT_EQ(0u, rx.bad) << "messages that arrived damaged";

    flush_ep(sender(), ep);
    dereg(sender(), memh);
}

_UCT_INSTANTIATE_TEST_CASE(test_cxi_am, cxi)
_UCT_INSTANTIATE_TEST_CASE(test_cxi_am_small_ring, cxi)
