/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching unit tests -- native rendezvous.
 *
 * Most tests here post the receiver's priority LE (tag_recv_zcopy) before
 * the sender issues uct_ep_tag_rndv_zcopy, so the transfer goes through the
 * direct-match path: C_EVENT_PUT or C_EVENT_PUT_OVERFLOW with
 * tgt_long.rendezvous==1, then C_EVENT_RENDEZVOUS, then a C_EVENT_REPLY
 * (either NIC-auto-issued or software-issued -- neither is controllable
 * from here, hardware alone decides get_issued, so tests do not assert on
 * which path fired).
 *
 * Genuinely unexpected rendezvous arrivals (no priority LE ever posted) are
 * supported via a separate mechanism: rndv_cb receives remote_addr/rkey_buf
 * for UCP's own later generic uct_ep_get_zcopy/get_bcopy pull, and the
 * per-send header (ep_id/req_id/md_index) is delivered via req_id riding
 * header_data on every rendezvous Put plus a one-time-per-ep control-
 * message announce for ep_id/md_index (see uct_cxi_ep_send_rndv_hdr_
 * announce, cxi_am.c, and uct_cxi_rndv_unexp_pending_t, cxi_tag.h, for the
 * announce-vs-Put race this implies). cancel_unmatched below only exercises
 * the sender-side cancel bookkeeping for this path; dedicated coverage of
 * rndv_cb's own data/header correctness is tracked separately.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_tag.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>
#include <uct/cxi/base/cxi_tag.h>

#include <cstring>
#include <vector>
#include <unistd.h>


namespace {

/** Build a real 17-byte offload rendezvous header (uct_cxi_rndv_hdr_wire_t's
 * exact on-wire layout), matching what UCP always supplies to
 * uct_ep_tag_rndv_zcopy() on every call -- see cxi_tag.h. Tests that don't
 * care about header content (every direct/delayed-match test below) still
 * need a real, correctly-sized buffer: uct_ep_tag_rndv_zcopy() asserts
 * header_length >= sizeof(uct_cxi_rndv_hdr_wire_t) unconditionally now that
 * req_id always travels via header_data and ep_id/md_index always trigger
 * this ep's one-time announce (see uct_cxi_ep_send_rndv_hdr_announce,
 * cxi_am.c) -- NULL/0 (a holdover from when the header argument was
 * genuinely unused) would trip that assert on the very first send. */
std::vector<uint8_t> pack_rndv_hdr(uint64_t ep_id, uint64_t req_id,
                                   uint8_t md_index)
{
    uct_cxi_rndv_hdr_wire_t hdr;
    hdr.ep_id    = ep_id;
    hdr.req_id   = req_id;
    hdr.md_index = md_index;

    std::vector<uint8_t> buf(sizeof(hdr));
    memcpy(buf.data(), &hdr, sizeof(hdr));
    return buf;
}

} // namespace


class test_cxi_tag_rndv : public test_cxi_tag_base {
protected:
    void init() override
    {
        test_cxi_tag_base::init();
        check_caps_skip(UCT_IFACE_FLAG_TAG_RNDV_ZCOPY);
    }

    /** Post a direct-match priority LE, issue rndv_zcopy, and drive both
     * sides to completion. Returns once both the receiver's completed_cb
     * and the sender's rndv comp have fired. */
    void do_rndv_zcopy(size_t tx_len, size_t rx_len, uct_tag_t tag,
                       uct_cxi_tag_recv_ctx &rctx,
                       uct_cxi_rndv_send_ctx &sctx,
                       std::vector<uint8_t> &rx_buf,
                       std::vector<uint8_t> &tx_buf, uct_mem_h &rx_memh,
                       uct_mem_h &tx_memh)
    {
        sender().connect_to_iface(0, receiver());
        uct_ep_h ep = sender().ep(0);

        rx_memh = reg(receiver(), rx_buf.data(), rx_len);
        init_recv_ctx(rctx);

        uct_iov_t riov;
        riov.buffer = rx_buf.data();
        riov.length = rx_len;
        riov.memh   = rx_memh;
        riov.stride = 0;
        riov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), tag,
                                               UCS_MASK(64), &riov, 1,
                                               &rctx.super));

        tx_memh = reg(sender(), tx_buf.data(), tx_len);
        init_rndv_send_ctx(sctx);

        uct_iov_t siov;
        siov.buffer = tx_buf.data();
        siov.length = tx_len;
        siov.memh   = tx_memh;
        siov.stride = 0;
        siov.count  = 1;

        std::vector<uint8_t> hdr = pack_rndv_hdr(0x1111111111111111ULL, tag,
                                                 1);
        ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, tag, hdr.data(),
                                                    hdr.size(), &siov,
                                                    1, 0, &sctx.super);
        ASSERT_FALSE(UCS_PTR_IS_ERR(sp))
                << "rndv_zcopy failed: "
                << ucs_status_string(UCS_PTR_STATUS(sp));

        poll_until(rctx.completed);
        poll_until(sctx.fired);
    }
};


/* -------------------------------------------------------------------------
 * Direct match: full round trip, both sides observe completion
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag_rndv, direct_match_small)
{
    static const uct_tag_t TAG     = 0xAA11223344556677ULL;
    static const size_t    PAY_LEN = 512;
    static const uint8_t   FILL    = 0x5C;

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    uct_mem_h             rx_memh, tx_memh;
    uct_cxi_tag_recv_ctx   rctx;
    uct_cxi_rndv_send_ctx  sctx;

    do_rndv_zcopy(PAY_LEN, PAY_LEN, TAG, rctx, sctx, rx_buf, tx_buf, rx_memh,
                 tx_memh);

    EXPECT_TRUE(rctx.consumed);
    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(0ULL, rctx.imm) << "imm is always 0 for rendezvous";
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    EXPECT_EQ(UCS_OK, sctx.super.status)
            << "sender comp must confirm the peer's Get, not just local "
               "submission";
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }

    dereg(receiver(), rx_memh);
    dereg(sender(), tx_memh);
    flush_ep(sender(), sender().ep(0));
}

UCS_TEST_P(test_cxi_tag_rndv, direct_match_large)
{
    static const uct_tag_t TAG     = 0xBB22334455667788ULL;
    static const size_t    PAY_LEN = 512 * 1024;
    static const uint8_t   FILL    = 0xE3;

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    uct_mem_h             rx_memh, tx_memh;
    uct_cxi_tag_recv_ctx   rctx;
    uct_cxi_rndv_send_ctx  sctx;

    do_rndv_zcopy(PAY_LEN, PAY_LEN, TAG, rctx, sctx, rx_buf, tx_buf, rx_memh,
                 tx_memh);

    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    EXPECT_EQ(UCS_OK, sctx.super.status);
    for (size_t i = 0; i < PAY_LEN; i += 4096) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }
    EXPECT_EQ(FILL, rx_buf[PAY_LEN - 1]) << "last byte mismatch";

    dereg(receiver(), rx_memh);
    dereg(sender(), tx_memh);
    flush_ep(sender(), sender().ep(0));
}


/* -------------------------------------------------------------------------
 * Truncation: posted buffer smaller than the rendezvous message.
 *
 * Regression coverage for a real bug found while designing this suite:
 * uct_cxi_iface_issue_rdzv_get() originally computed the software-issued
 * Get's request_len purely from rlength-mlength (the message's own total
 * length), never consulting the posted buffer's actual capacity --
 * confirmed against libfabric's own issue_rdzv_get() (cxip_msg_hpc.c:
 * 369-457), which clamps via req->data_len = MIN(req->recv.ulen, rlength)
 * before computing request_len. Left unfixed, a truncating rendezvous
 * receive would DMA-write past the end of the destination buffer. A guard
 * region past the registered buffer, checked for corruption below, is a
 * regression check for exactly that -- not just a completion-status check.
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag_rndv, truncation)
{
    static const uct_tag_t TAG      = 0xCC33445566778899ULL;
    static const size_t    RX_LEN   = 256;
    static const size_t    TX_LEN   = 8192;
    static const size_t    GUARD_LEN = 4096;
    static const uint8_t   GUARD_FILL = 0xB6;

    /* rx_buf is intentionally oversized -- only the first RX_LEN bytes are
     * registered/posted, matching real usage. The bytes past RX_LEN are an
     * unregistered guard region: any hardware write there (the bug this
     * test targets) would corrupt this pattern even without a hard fault,
     * since the LAC's IOMMU/ATS translation may still resolve adjacent
     * process memory. */
    std::vector<uint8_t> rx_buf(RX_LEN + GUARD_LEN, GUARD_FILL);
    std::vector<uint8_t> tx_buf(TX_LEN, 0xEE);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h rx_memh = reg(receiver(), rx_buf.data(), RX_LEN);
    uct_cxi_tag_recv_ctx rctx;
    init_recv_ctx(rctx);

    uct_iov_t riov;
    riov.buffer = rx_buf.data();
    riov.length = RX_LEN;
    riov.memh   = rx_memh;
    riov.stride = 0;
    riov.count  = 1;
    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &riov, 1,
                                           &rctx.super));

    uct_mem_h tx_memh = reg(sender(), tx_buf.data(), TX_LEN);
    uct_cxi_rndv_send_ctx sctx;
    init_rndv_send_ctx(sctx);

    uct_iov_t siov;
    siov.buffer = tx_buf.data();
    siov.length = TX_LEN;
    siov.memh   = tx_memh;
    siov.stride = 0;
    siov.count  = 1;
    std::vector<uint8_t> hdr = pack_rndv_hdr(0x2222222222222222ULL, TAG, 2);
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, hdr.data(),
                                                hdr.size(), &siov, 1,
                                                0, &sctx.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(sp));

    poll_until(rctx.completed);
    poll_until(sctx.fired);

    EXPECT_EQ(UCS_ERR_MESSAGE_TRUNCATED, rctx.status);
    EXPECT_EQ(RX_LEN, rctx.length) << "delivered length must be capped at "
                                      "the posted buffer size";
    EXPECT_EQ(UCS_OK, sctx.super.status)
            << "the Get itself succeeds (it pulled exactly what was "
               "requested); truncation is a receiver-side status only";

    for (size_t i = 0; i < RX_LEN; i++) {
        EXPECT_EQ(0xEEu, rx_buf[i]) << "delivered byte " << i << " mismatch";
    }
    for (size_t i = RX_LEN; i < RX_LEN + GUARD_LEN; i++) {
        ASSERT_EQ(GUARD_FILL, rx_buf[i])
                << "guard byte at offset " << i
                << " corrupted -- rendezvous Get wrote past the posted "
                   "buffer's own capacity";
    }

    dereg(receiver(), rx_memh);
    dereg(sender(), tx_memh);
    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * Cancel: sender-side bookkeeping removal, no peer ever matches
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag_rndv, cancel_unmatched)
{
    static const uct_tag_t TAG     = 0xDD445566778899AAULL;
    static const size_t    PAY_LEN = 128;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx_buf(PAY_LEN, 0x11);
    uct_mem_h            tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
    uct_cxi_rndv_send_ctx sctx;
    init_rndv_send_ctx(sctx);

    uct_iov_t siov;
    siov.buffer = tx_buf.data();
    siov.length = PAY_LEN;
    siov.memh   = tx_memh;
    siov.stride = 0;
    siov.count  = 1;

    /* header/header_length: uct_ep_tag_rndv_zcopy() always requires a real
     * 17-byte header buffer now (ep_id/req_id/md_index -- see
     * uct_cxi_rndv_hdr_wire_t), regardless of whether a receive is ever
     * posted: req_id travels via header_data on this very Put, and
     * ep_id/md_index trigger a one-time control-message announce to the
     * peer on this ep's first rndv send (uct_cxi_ep_send_rndv_hdr_announce).
     * NULL/0, as this test originally passed (a holdover from when
     * unexpected rendezvous was unconditionally dropped and the header
     * argument was therefore irrelevant), would now trip the header_length
     * assert in uct_ep_tag_rndv_zcopy(). Content doesn't matter here --
     * this test only exercises sender-side cancel bookkeeping and never
     * inspects the reconstructed header. */
    std::vector<uint8_t> hdr_buf = pack_rndv_hdr(0x5555555555555555ULL, TAG,
                                                 5);

    /* No receiver posted for this tag -- the rendezvous Put lands in the
     * overflow ring and goes through the real unexpected-rendezvous
     * SEARCH_AND_DELETE/rndv_cb path (see test_cxi_tag.h's uct_cxi_tag_
     * rndv_cb stub), possibly racing this same ep's header announce (see
     * uct_cxi_rndv_unexp_pending_t in cxi_tag.h) -- either way, no receive
     * is ever posted to complete the data pull and no Get is ever issued
     * against this exposure, so cancelling here still exercises pure
     * sender-side bookkeeping removal with no hardware race possible. */
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, hdr_buf.data(),
                                                hdr_buf.size(), &siov, 1, 0,
                                                &sctx.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(sp));

    ASSERT_UCS_OK(uct_ep_tag_rndv_cancel(ep, sp));

    /* Confirm comp never fires for the cancelled op -- drain progress for
     * a short, bounded window. */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(1.0);
    while (ucs_get_time() < deadline) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_FALSE(sctx.fired) << "cancel must not invoke the completion "
                                "callback";

    /* Confirm the op-pool slot was actually reclaimed: repeat send+cancel
     * enough times to exceed a small pool's worth of entries if leaked. */
    for (int i = 0; i < 64; i++) {
        uct_cxi_rndv_send_ctx sctx2;
        init_rndv_send_ctx(sctx2);
        ucs_status_ptr_t sp2 = uct_ep_tag_rndv_zcopy(ep, TAG, hdr_buf.data(),
                                                     hdr_buf.size(), &siov, 1,
                                                     0, &sctx2.super);
        ASSERT_FALSE(UCS_PTR_IS_ERR(sp2))
                << "iteration " << i << ": rndv_zcopy failed -- possible "
                   "op_pool leak from a prior cancel";
        ASSERT_UCS_OK(uct_ep_tag_rndv_cancel(ep, sp2));
    }

    dereg(sender(), tx_memh);
    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * Multiple concurrent outstanding sends -- exercises the address-keyed
 * linear-scan correlation in uct_cxi_iface_tag_handle_rdzv_get() under
 * concurrency: each send's completion must be matched back to the right
 * uct_cxi_rdzv_op_t by start address, never cross-wired.
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag_rndv, multiple_outstanding)
{
    static const size_t N       = 8;
    static const size_t PAY_LEN = 1024;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<std::vector<uint8_t> > rx_bufs(N), tx_bufs(N);
    std::vector<uct_mem_h>             rx_memh(N), tx_memh(N);
    std::vector<uct_cxi_tag_recv_ctx>  rctx(N);
    std::vector<uct_cxi_rndv_send_ctx> sctx(N);
    std::vector<uct_tag_t>             tags(N);

    for (size_t i = 0; i < N; i++) {
        tags[i]    = 0xEE00000000000000ULL | i;
        rx_bufs[i].assign(PAY_LEN, 0);
        tx_bufs[i].assign(PAY_LEN, static_cast<uint8_t>(0x10 + i));

        rx_memh[i] = reg(receiver(), rx_bufs[i].data(), PAY_LEN);
        init_recv_ctx(rctx[i]);

        uct_iov_t riov;
        riov.buffer = rx_bufs[i].data();
        riov.length = PAY_LEN;
        riov.memh   = rx_memh[i];
        riov.stride = 0;
        riov.count  = 1;
        ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), tags[i],
                                               UCS_MASK(64), &riov, 1,
                                               &rctx[i].super));
    }

    /* Issue all N rendezvous sends before any completes, so they are
     * genuinely concurrent in iface->rdzv.outstanding. */
    for (size_t i = 0; i < N; i++) {
        tx_memh[i] = reg(sender(), tx_bufs[i].data(), PAY_LEN);
        init_rndv_send_ctx(sctx[i]);

        uct_iov_t siov;
        siov.buffer = tx_bufs[i].data();
        siov.length = PAY_LEN;
        siov.memh   = tx_memh[i];
        siov.stride = 0;
        siov.count  = 1;
        std::vector<uint8_t> hdr = pack_rndv_hdr(0x3333333333333333ULL,
                                                 tags[i], 3);
        ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, tags[i], hdr.data(),
                                                    hdr.size(), &siov, 1, 0,
                                                    &sctx[i].super);
        ASSERT_FALSE(UCS_PTR_IS_ERR(sp)) << "send " << i << " failed";
    }

    for (size_t i = 0; i < N; i++) {
        poll_until(rctx[i].completed);
        poll_until(sctx[i].fired);
    }

    for (size_t i = 0; i < N; i++) {
        EXPECT_EQ(tags[i], rctx[i].stag) << "send " << i;
        EXPECT_EQ(PAY_LEN, rctx[i].length) << "send " << i;
        EXPECT_EQ(UCS_OK, rctx[i].status) << "send " << i;
        EXPECT_EQ(UCS_OK, sctx[i].super.status) << "send " << i;
        for (size_t b = 0; b < PAY_LEN; b++) {
            ASSERT_EQ(static_cast<uint8_t>(0x10 + i), rx_bufs[i][b])
                    << "send " << i << " byte " << b
                    << " -- cross-wired with a different outstanding send?";
        }
        dereg(receiver(), rx_memh[i]);
        dereg(sender(), tx_memh[i]);
    }

    flush_ep(sender(), ep);
}


/* -------------------------------------------------------------------------
 * rndv_request: deliberately stubbed for this increment (see the design
 * plan's "Current increment" section) -- confirm it fails cleanly rather
 * than corrupting or hanging, per ucp_rndv_send_handle_status_from_pending's
 * own handling of UCS_ERR_UNSUPPORTED.
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_tag_rndv, rndv_request_unsupported)
{
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    ucs_status_t status = uct_ep_tag_rndv_request(ep, 0x1234, NULL, 0, 0);
    EXPECT_EQ(UCS_ERR_UNSUPPORTED, status);
}


/* -------------------------------------------------------------------------
 * Diagnostic: delayed-matched rendezvous -- the rendezvous Put physically
 * lands (in the overflow ring, mlength=0) before the matching receive is
 * ever posted, then the priority-LE APPEND races hardware's own delayed
 * correlation. Confirms this still completes correctly and checks whether
 * the NIC auto-issues the Get or leaves it to software (get_issued=0/1 --
 * hardware's own decision, not asserted on directly; see this class's own
 * header comment on why direct-match tests don't assert on it either). Run
 * with UCX_LOG_LEVEL=debug and grep the resulting "[RENDEZVOUS]" log line's
 * get_issued=%u field for the answer.
 *
 * Same ordering discipline as test_cxi_tag's delayed_match_data_copy: no
 * receiver-side progress at all until after the receive is posted, so the
 * rendezvous Put is guaranteed (by real elapsed time) to have already
 * landed before uct_iface_tag_recv_zcopy ever runs.
 */
UCS_TEST_P(test_cxi_tag_rndv, delayed_match_get_issued)
{
    static const uct_tag_t TAG     = 0xEE55667788990011ULL;
    static const size_t    PAY_LEN = 512;
    static const uint8_t   FILL    = 0x3D;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    uct_mem_h            tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
    uct_cxi_rndv_send_ctx sctx;
    init_rndv_send_ctx(sctx);

    uct_iov_t siov;
    siov.buffer = tx_buf.data();
    siov.length = PAY_LEN;
    siov.memh   = tx_memh;
    siov.stride = 0;
    siov.count  = 1;

    std::vector<uint8_t> hdr = pack_rndv_hdr(0x4444444444444444ULL, TAG, 4);
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, hdr.data(),
                                                hdr.size(), &siov, 1,
                                                0, &sctx.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(sp));

    usleep(100000); /* 100 ms, real elapsed time, no progress calls */

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
    uct_cxi_tag_recv_ctx  rctx;
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

    poll_until(rctx.completed, 5.0);
    poll_until(sctx.fired, 5.0);

    EXPECT_EQ(TAG, rctx.stag);
    EXPECT_EQ(PAY_LEN, rctx.length);
    EXPECT_EQ(UCS_OK, rctx.status);
    EXPECT_EQ(UCS_OK, sctx.super.status);
    for (size_t i = 0; i < PAY_LEN; i++) {
        EXPECT_EQ(FILL, rx_buf[i]) << "byte " << i << " mismatch";
    }

    dereg(receiver(), rx_memh);
    dereg(sender(), tx_memh);
    flush_ep(sender(), ep);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_rndv, cxi)


/* -------------------------------------------------------------------------
 * Genuinely unexpected rendezvous: no priority LE ever posted for any of
 * these tags. Exercises rndv_cb's own header/data correctness end to end --
 * something no test above does (they either post a receive first, or, for
 * cancel_unmatched, cancel before any data ever needs to move). Needs a
 * richer rndv_cb than uct_cxi_tag_rndv_cb's no-op stub (test_cxi_tag.h): one
 * that captures the reconstructed header and unpacks rkey_buf immediately
 * (both are only valid for the duration of the callback -- rkey_buf in
 * particular points at a stack uct_cxi_rkey_t inside the transport, see
 * uct_cxi_iface_tag_handle_search_delete_confirm_rndv/uct_cxi_iface_rndv_
 * unexp_pending_drain in cxi_tag.c), so a real generic uct_ep_get_zcopy pull
 * can be driven later, from the test body, exactly as UCP itself would.
 * -------------------------------------------------------------------------
 */

namespace {

struct rndv_arrival_record {
    uct_tag_t         tag;
    uint64_t          ep_id;
    uint64_t          req_id;
    uint8_t           md_index;
    uint64_t          remote_addr;
    size_t            length;
    uct_rkey_bundle_t rkey_bundle;
};

struct rndv_arrival_ctx {
    uct_component_h                  component;
    std::vector<rndv_arrival_record> records;
};

ucs_status_t unexp_rndv_eager_cb(void *arg, void *data, size_t length,
                                 unsigned flags, uct_tag_t stag, uint64_t imm,
                                 void **context)
{
    /* Unused by these tests -- present only because create_entity()
     * requires a real callback (see test_cxi_tag.h's identical stub). */
    return UCS_OK;
}

ucs_status_t unexp_rndv_cb(void *arg, unsigned flags, uint64_t stag,
                           const void *header, unsigned header_length,
                           uint64_t remote_addr, size_t length,
                           const void *rkey_buf)
{
    rndv_arrival_ctx *ctx = static_cast<rndv_arrival_ctx *>(arg);
    rndv_arrival_record rec;

    EXPECT_GE(header_length, sizeof(uct_cxi_rndv_hdr_wire_t))
            << "rndv_cb header shorter than a real offload header";
    if (header_length >= sizeof(uct_cxi_rndv_hdr_wire_t)) {
        const uct_cxi_rndv_hdr_wire_t *hdr_w =
                static_cast<const uct_cxi_rndv_hdr_wire_t *>(header);
        rec.ep_id    = hdr_w->ep_id;
        rec.req_id   = hdr_w->req_id;
        rec.md_index = hdr_w->md_index;
    } else {
        rec.ep_id = rec.req_id = 0;
        rec.md_index           = 0;
    }
    rec.tag         = stag;
    rec.remote_addr = remote_addr;
    rec.length      = length;

    /* rkey_buf is only valid for this call -- unpack now (copies the bytes
     * into a fresh heap allocation) so the test body can still use it after
     * this callback returns, to drive the actual data pull. */
    EXPECT_UCS_OK(uct_rkey_unpack(ctx->component, rkey_buf, &rec.rkey_bundle));

    ctx->records.push_back(rec);
    return UCS_OK;
}

} // namespace


class test_cxi_tag_rndv_unexp : public test_cxi_rma_base {
protected:
    rndv_arrival_ctx m_ctx;

    void init() override
    {
        /* Deliberately not calling test_cxi_rma_base::init() -- it uses the
         * no-arg create_entity(), which substitutes dummy eager/rndv
         * callbacks we can't observe (same reasoning as test_cxi_tag_base's
         * own init()). */
        uct_test::init();
        m_ctx.component = GetParam()->component;
        m_entities.push_back(uct_test::create_entity(
                0, NULL, unexp_rndv_eager_cb, unexp_rndv_cb, &m_ctx,
                &m_ctx)); /* sender   */
        m_entities.push_back(uct_test::create_entity(
                0, NULL, unexp_rndv_eager_cb, unexp_rndv_cb, &m_ctx,
                &m_ctx)); /* receiver */

        check_caps_skip(UCT_IFACE_FLAG_TAG_RNDV_ZCOPY);
    }

    /** Poll sender + receiver progress until @a flag is set or timeout
     * (mirrors test_cxi_tag_base's own helper -- not available here since
     * this fixture derives from test_cxi_rma_base instead). */
    void poll_until(volatile bool &flag, double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);
        while (!flag && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_TRUE(flag) << "condition not met after " << timeout_sec
                          << " s";
    }

    /** Poll sender + receiver progress until at least @a n unexpected
     * rendezvous arrivals have been captured, or timeout. */
    void poll_until_count(size_t n, double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);
        while ((m_ctx.records.size() < n) && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_GE(m_ctx.records.size(), n)
                << "only " << m_ctx.records.size() << "/" << n
                << " unexpected rendezvous arrivals delivered after "
                << timeout_sec << " s";
    }

    /** Drive the actual data pull for one captured arrival, exactly as UCP
     * itself would once a matching receive is posted: a generic
     * uct_ep_get_zcopy on the receiver's own ep back to the sender, using
     * the rkey/remote_addr rndv_cb reported. Releases the rkey bundle
     * before returning. */
    void pull_and_verify(uct_ep_h rep, const rndv_arrival_record &rec,
                         std::vector<uint8_t> &dst, uct_mem_h dst_memh,
                         const std::vector<uint8_t> &expected)
    {
        struct pull_ctx {
            uct_completion_t super;
            volatile bool     fired;
        } pctx;
        memset(&pctx, 0, sizeof(pctx));
        pctx.super.func = +[](uct_completion_t *self) {
            reinterpret_cast<pull_ctx *>(self)->fired = true;
        };
        pctx.super.count  = 1;
        pctx.super.status = UCS_OK;

        uct_iov_t iov;
        iov.buffer = dst.data();
        iov.length = rec.length;
        iov.memh   = dst_memh;
        iov.stride = 0;
        iov.count  = 1;

        ucs_status_t status = uct_ep_get_zcopy(rep, &iov, 1, rec.remote_addr,
                                               rec.rkey_bundle.rkey,
                                               &pctx.super);
        ASSERT_EQ(UCS_INPROGRESS, (int)status)
                << "generic get_zcopy for the unexpected-rndv pull failed: "
                << ucs_status_string(status);

        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        while (!pctx.fired && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_TRUE(pctx.fired) << "unexpected-rndv data pull never "
                                   "completed";
        EXPECT_EQ(UCS_OK, pctx.super.status);
        ASSERT_EQ(expected.size(), rec.length);
        for (size_t i = 0; i < rec.length; i++) {
            EXPECT_EQ(expected[i], dst[i]) << "byte " << i << " mismatch";
        }

        uct_rkey_release(m_ctx.component, &rec.rkey_bundle);
    }
};


/*
 * Single unexpected rendezvous send, no receive ever posted -- the "cold
 * start" case: this ep's very first rndv send, so the header announce and
 * the rendezvous Put race (see uct_cxi_rndv_unexp_pending_t in cxi_tag.h).
 * Verifies rndv_cb reports the real header/tag/length, and that the actual
 * payload arrives correctly through UCP's own generic pull mechanism
 * (cxi_rma.c's is_rndv rkey routing), independently of this transport's
 * internal matched-receive Get path.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, cold_start)
{
    static const uct_tag_t TAG     = 0xF00D000000000001ULL;
    static const size_t    PAY_LEN = 4096;
    static const uint8_t   FILL    = 0x6A;
    static const uint64_t  EP_ID   = 0xABCDEF0123456789ULL;
    static const uint64_t  REQ_ID  = 0x1122334455667788ULL;
    static const uint8_t   MD_IDX  = 7;

    sender().connect_to_iface(0, receiver());
    receiver().connect_to_iface(0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    uct_mem_h            tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
    uct_cxi_rndv_send_ctx sctx;
    init_rndv_send_ctx(sctx);

    std::vector<uint8_t> hdr = pack_rndv_hdr(EP_ID, REQ_ID, MD_IDX);
    uct_iov_t siov;
    siov.buffer = tx_buf.data();
    siov.length = PAY_LEN;
    siov.memh   = tx_memh;
    siov.stride = 0;
    siov.count  = 1;
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(sep, TAG, hdr.data(),
                                                hdr.size(), &siov, 1, 0,
                                                &sctx.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(sp));

    poll_until_count(1);
    ASSERT_EQ(1u, m_ctx.records.size());

    const rndv_arrival_record &rec = m_ctx.records[0];
    EXPECT_EQ(TAG, rec.tag);
    EXPECT_EQ(EP_ID, rec.ep_id);
    EXPECT_EQ(REQ_ID, rec.req_id);
    EXPECT_EQ(MD_IDX, rec.md_index);
    EXPECT_EQ(PAY_LEN, rec.length);

    std::vector<uint8_t> dst(PAY_LEN, 0);
    uct_mem_h             dst_memh = reg(receiver(), dst.data(), PAY_LEN);
    pull_and_verify(rep, rec, dst, dst_memh, tx_buf);

    poll_until(sctx.fired);
    EXPECT_EQ(UCS_OK, sctx.super.status)
            << "sender's own rndv_zcopy completion must fire once UCP's "
               "generic pull lands, exactly as for a matched receive";

    dereg(receiver(), dst_memh);
    dereg(sender(), tx_memh);
    flush_ep(sender(), sep);
}


/*
 * Multiple unexpected rendezvous sends on the same ep, all with the same
 * ep_id/md_index (as UCP itself would -- both are constant for the life of
 * a UCP connection) but distinct req_id per send. Confirms the per-peer
 * header cache (iface->tag.rndv_peer_cache) reconstructs a *consistent*
 * ep_id/md_index across every arrival while req_id tracks each individual
 * send correctly -- the core correctness property the one-time announce
 * design depends on. All N sends are issued back to back before any
 * progress() call, so the first few arrivals likely race this ep's single
 * announce (see uct_cxi_rndv_unexp_pending_t's pending-queue path,
 * cxi_tag.c) while the rest hit an already-populated cache -- both cases
 * are exercised without needing to force either one explicitly.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, multiple_same_ep_id_md_index)
{
    static const size_t   N       = 6;
    static const size_t   PAY_LEN = 512;
    static const uint64_t EP_ID   = 0x99AA99AA99AA99AAULL;
    static const uint8_t  MD_IDX  = 42;

    sender().connect_to_iface(0, receiver());
    receiver().connect_to_iface(0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    std::vector<std::vector<uint8_t> > tx_bufs(N);
    std::vector<uct_mem_h>             tx_memh(N);
    std::vector<uct_cxi_rndv_send_ctx> sctx(N);
    std::vector<uct_tag_t>             tags(N);
    std::vector<uint64_t>              req_ids(N);

    for (size_t i = 0; i < N; i++) {
        tags[i]    = 0xF00D000000000100ULL | i;
        req_ids[i] = 0x7000000000000000ULL | (i * 0x11ULL);
        tx_bufs[i].assign(PAY_LEN, static_cast<uint8_t>(0x50 + i));
        tx_memh[i] = reg(sender(), tx_bufs[i].data(), PAY_LEN);
        init_rndv_send_ctx(sctx[i]);
    }

    /* Issue all N sends before any progress() call -- genuinely pipelined,
     * same technique as test_cxi_tag_rndv.multiple_outstanding. */
    for (size_t i = 0; i < N; i++) {
        std::vector<uint8_t> hdr = pack_rndv_hdr(EP_ID, req_ids[i], MD_IDX);
        uct_iov_t             siov;
        siov.buffer = tx_bufs[i].data();
        siov.length = PAY_LEN;
        siov.memh   = tx_memh[i];
        siov.stride = 0;
        siov.count  = 1;
        ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(sep, tags[i], hdr.data(),
                                                    hdr.size(), &siov, 1, 0,
                                                    &sctx[i].super);
        ASSERT_FALSE(UCS_PTR_IS_ERR(sp)) << "send " << i << " failed";
    }

    /* None of these tags ever get a receive posted -- every one is
     * genuinely unexpected. */
    poll_until_count(N);
    ASSERT_EQ(N, m_ctx.records.size());

    /* Delivery order isn't guaranteed (concurrent sends, real hardware) --
     * match records back to sends by tag. */
    for (size_t r = 0; r < N; r++) {
        const rndv_arrival_record &rec = m_ctx.records[r];
        size_t                     idx = N;

        for (size_t i = 0; i < N; i++) {
            if (tags[i] == rec.tag) {
                idx = i;
                break;
            }
        }
        ASSERT_LT(idx, N) << "record " << r << " tag=0x" << std::hex
                          << rec.tag << " matches no send";

        EXPECT_EQ(EP_ID, rec.ep_id)
                << "record " << r << " (send " << idx << "): ep_id must be "
                   "identical across every send on this ep";
        EXPECT_EQ(MD_IDX, rec.md_index)
                << "record " << r << " (send " << idx << "): md_index must "
                   "be identical across every send on this ep";
        EXPECT_EQ(req_ids[idx], rec.req_id)
                << "record " << r << " (send " << idx << "): req_id must "
                   "match this specific send, not some other one";
        EXPECT_EQ(PAY_LEN, rec.length) << "record " << r;

        std::vector<uint8_t> dst(PAY_LEN, 0);
        uct_mem_h             dst_memh = reg(receiver(), dst.data(), PAY_LEN);
        pull_and_verify(rep, rec, dst, dst_memh, tx_bufs[idx]);
        dereg(receiver(), dst_memh);
    }

    for (size_t i = 0; i < N; i++) {
        poll_until(sctx[i].fired);
        EXPECT_EQ(UCS_OK, sctx[i].super.status) << "send " << i;
        dereg(sender(), tx_memh[i]);
    }

    flush_ep(sender(), sep);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_rndv_unexp, cxi)
