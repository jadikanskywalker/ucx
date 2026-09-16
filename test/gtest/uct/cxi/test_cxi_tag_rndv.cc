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

#include <cstring>
#include <vector>
#include <unistd.h>


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

        ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, tag, NULL, 0, &siov,
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
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, NULL, 0, &siov, 1,
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
    static const size_t HDR_LEN = sizeof(uint64_t) + sizeof(uint64_t) +
                                  sizeof(uint8_t); /* mirrors
                                  ucp_tag_offload_unexp_rndv_hdr_t /
                                  uct_cxi_rndv_hdr_wire_t's 17-byte layout */
    std::vector<uint8_t> hdr_buf(HDR_LEN, 0x77);

    /* No receiver posted for this tag -- the rendezvous Put lands in the
     * overflow ring and goes through the real unexpected-rendezvous
     * SEARCH_AND_DELETE/rndv_cb path (see test_cxi_tag.h's uct_cxi_tag_
     * rndv_cb stub), possibly racing this same ep's header announce (see
     * uct_cxi_rndv_unexp_pending_t in cxi_tag.h) -- either way, no receive
     * is ever posted to complete the data pull and no Get is ever issued
     * against this exposure, so cancelling here still exercises pure
     * sender-side bookkeeping removal with no hardware race possible. */
    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, hdr_buf.data(),
                                                HDR_LEN, &siov, 1, 0,
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
                                                     HDR_LEN, &siov, 1, 0,
                                                     &sctx2.super);
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
        ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, tags[i], NULL, 0,
                                                    &siov, 1, 0,
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
 * Diagnostic: delayed-matched rendezvous -- does the NIC still auto-issue
 * the Get, or does get_issued come back 0 (the software-issue path, never
 * empirically observed on real hardware in this whole engagement -- every
 * prior test here is direct-match, receive posted first, and every
 * completion observed so far has been get_issued==1)?
 *
 * This is genuinely exploratory, not a known-good regression test: this
 * file's own header documents unexpected/overflow rendezvous arrivals as
 * out of scope, silently dropped by tag_handle_ovf_arrival()'s early
 * return for event->tgt_long.rendezvous -- but that drop only touches the
 * *initial* C_EVENT_PUT/PUT_OVERFLOW arrival (always a 0-byte eager
 * prefix for this transport's rendezvous Puts, see uct_ep_tag_rndv_zcopy),
 * not the later C_EVENT_RENDEZVOUS/C_EVENT_REPLY events, which are routed
 * to tag_handle_rdzv_match() regardless of arrival timing, and whose
 * completion gate only requires those two (not the dropped Put) -- so this
 * *might* already complete correctly today. Whether it does, and whether
 * the eventual Get was NIC-auto-issued or not, is exactly what this test
 * is for. Run with UCX_LOG_LEVEL=debug and grep the resulting
 * "[RENDEZVOUS]" log line's get_issued=%u field for the answer -- it is
 * not asserted on directly here since it is hardware's own decision, not
 * something a passing/failing assertion should gate on either way (see
 * this class's own header comment on why direct-match tests don't assert
 * on it either).
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

    ucs_status_ptr_t sp = uct_ep_tag_rndv_zcopy(ep, TAG, NULL, 0, &siov, 1,
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
