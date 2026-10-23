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
 * announce, cxi_am.c, and uct_cxi_unexp_report_t, cxi_tag.h, for the
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
extern "C" {
#include <uct/cxi/base/cxi_tag.h>
}

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
        cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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
     * uct_cxi_unexp_report_t in cxi_tag.h) -- either way, no receive
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

    cxi_connect(sender(), 0, receiver());
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

    cxi_connect(sender(), 0, receiver());
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
 * uct_cxi_unexp_report in cxi_tag.c), so a real generic uct_ep_get_zcopy pull
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

/* One unexpected message as UCP is told about it, in the order it is told. */
struct unexp_arrival {
    bool      rndv;
    uct_tag_t tag;
    uint64_t  id;     /* rendezvous: req_id; eager: first 8 payload bytes */
};

struct rndv_arrival_ctx {
    uct_component_h                  component;
    std::vector<rndv_arrival_record> records;
    std::vector<unexp_arrival>       order;   /* eager and rendezvous alike */
};

ucs_status_t unexp_rndv_eager_cb(void *arg, void *data, size_t length,
                                 unsigned flags, uct_tag_t stag, uint64_t imm,
                                 void **context)
{
    /* Only the order of arrival is of interest, see unexp_arrival. The
     * payload is not kept: eager_cb must not retain the pointer. */
    rndv_arrival_ctx *ctx = static_cast<rndv_arrival_ctx *>(arg);
    unexp_arrival     a   = {false, stag, 0};

    if (length >= sizeof(a.id)) {
        memcpy(&a.id, data, sizeof(a.id));
    }
    ctx->order.push_back(a);
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
    unexp_arrival a = {true, stag, rec.req_id};
    ctx->order.push_back(a);
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

    /** Poll sender + receiver progress until @a n unexpected messages of
     * either kind have been reported, or timeout. */
    void poll_until_count_arrivals(size_t n, double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);
        while ((m_ctx.order.size() < n) && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_GE(m_ctx.order.size(), n)
                << "only " << m_ctx.order.size() << "/" << n
                << " unexpected messages reported after " << timeout_sec
                << " s";
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
 * the rendezvous Put race (see uct_cxi_unexp_report_t in cxi_tag.h).
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

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
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
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
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
 * announce (an unexpected rendezvous waits for it, see uct_cxi_unexp_report_t
 * in cxi_tag.h) while the rest hit an already-populated cache -- both cases
 * are exercised without needing to force either one explicitly.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, multiple_same_ep_id_md_index)
{
    static const size_t   N       = 6;
    static const size_t   PAY_LEN = 512;
    static const uint64_t EP_ID   = 0x99AA99AA99AA99AAULL;
    static const uint8_t  MD_IDX  = 42;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
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
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}


/*
 * What a test needs to keep of an unexpected rendezvous send, until it has
 * pulled the data like UCP would and the send has completed: no receive is
 * ever posted for these, so they are only ever reported through rndv_cb.
 */
struct unexp_rndv_send {
    std::vector<uint8_t>  buf;
    uct_mem_h             memh;
    uct_cxi_rndv_send_ctx ctx;
};

/*
 * UCP matches unexpected messages in the order it is told of them, so an
 * unexpected rendezvous must be reported before a message with the same tag
 * that the same sender sent after it. The rendezvous is reported a round
 * trip late (its source address has to be read from the sender); an eager
 * message behind it is not delayed by anything, and so is reported first
 * unless it is held back.
 *
 * Only messages with the same tag are ordered: other tags are not held up
 * (what UCP does with a receive that matches several is its own affair). So
 * the eager message is sent once with the same tag, where the order is
 * checked, and once with another, where all that is checked is that
 * everything gets reported.
 *
 * A rendezvous, an eager message and another rendezvous (with a tag of its
 * own) are sent back to back without waiting for any of them, as UCP lets a
 * sender do. The last matters: when it arrives the eager message is already
 * waiting behind the first rendezvous, and the interface looks at what can be
 * reported -- it must not be tempted by the eager message.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, eager_is_not_reported_before_rendezvous)
{
    static const uct_tag_t TAGS[]   = {0xAAA0000000000001ULL,
                                       0xBBB0000000000002ULL};
    static const size_t    PAY_LEN  = 4096;
    static const unsigned  REPEATS  = 20;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    for (unsigned t = 0; t < 2; t++) {
        for (unsigned i = 0; i < REPEATS; i++) {
            const uct_tag_t tag1      = TAGS[0] + (i << 8);
            const uct_tag_t eager_tag = (t == 0) ? tag1 : TAGS[1] + (i << 8);
            /* Same tag for all three in the first round: one stream. */
            const uct_tag_t tag2      = (t == 0) ? tag1 :
                                        TAGS[0] + (i << 8) + 0x10000;
            const size_t    before    = m_ctx.order.size();
            const char     *what      = t ? "other tag" : "same tag";
            unexp_rndv_send rs[2];
            uct_tag_t       rtag[2] = {tag1, tag2};

            for (unsigned r = 0; r < 2; r++) {
                rs[r].buf.assign(PAY_LEN, (uint8_t)(0x5C + r));
                rs[r].memh = reg(sender(), rs[r].buf.data(), PAY_LEN);
                init_rndv_send_ctx(rs[r].ctx);
            }

            /* rendezvous, eager, rendezvous */
            for (unsigned k = 0; k < 3; k++) {
                if (k == 1) {
                    uint64_t marker = 0xE000 + i;
                    ASSERT_UCS_OK(uct_ep_tag_eager_short(sep, eager_tag,
                                                         &marker,
                                                         sizeof(marker)));
                    continue;
                }

                unsigned  r = k / 2;
                uct_iov_t siov;
                siov.buffer = rs[r].buf.data();
                siov.length = PAY_LEN;
                siov.memh   = rs[r].memh;
                siov.stride = 0;
                siov.count  = 1;
                std::vector<uint8_t> hdr = pack_rndv_hdr(0x77,
                                                         0x1000 * (r + 1) + i,
                                                         3);
                ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                        sep, rtag[r], hdr.data(), hdr.size(), &siov, 1, 0,
                        &rs[r].ctx.super)));
            }

            poll_until_count_arrivals(before + 3);
            ASSERT_EQ(before + 3, m_ctx.order.size());

            /* Where each of the three was reported, -1 if it was not. */
            int pos_r1 = -1, pos_eager = -1, pos_r2 = -1;
            for (unsigned k = 0; k < 3; k++) {
                const unexp_arrival &a = m_ctx.order[before + k];

                if (a.rndv && (a.tag == tag1) && (a.id == 0x1000 + i)) {
                    pos_r1 = k;
                } else if (!a.rndv && (a.tag == eager_tag)) {
                    pos_eager = k;
                    EXPECT_EQ(0xE000 + i, a.id);
                } else if (a.rndv && (a.tag == tag2) &&
                           (a.id == 0x2000 + i)) {
                    pos_r2 = k;
                }
            }
            EXPECT_TRUE((pos_r1 >= 0) && (pos_eager >= 0) && (pos_r2 >= 0))
                    << "round " << i << " (" << what << "): not all three "
                    << "messages were reported once";
            if (t == 0) {
                EXPECT_LT(pos_r1, pos_eager)
                        << "round " << i << ": the eager message was "
                        << "reported ahead of the rendezvous with its tag "
                        << "that was sent before it";
                EXPECT_LT(pos_eager, pos_r2)
                        << "round " << i << ": the rendezvous sent after the "
                        << "eager message with its tag was reported ahead "
                        << "of it";
            }

            /* Complete both rendezvous like UCP would. */
            for (unsigned r = 0; r < 2; r++) {
                const rndv_arrival_record *rec = NULL;
                for (size_t k = m_ctx.records.size(); k-- > 0;) {
                    if ((m_ctx.records[k].tag == rtag[r]) &&
                        (m_ctx.records[k].req_id == 0x1000 * (r + 1) + i)) {
                        rec = &m_ctx.records[k];
                        break;
                    }
                }
                ASSERT_NE(nullptr, rec);

                std::vector<uint8_t> dst(PAY_LEN, 0);
                uct_mem_h dmemh = reg(receiver(), dst.data(), PAY_LEN);

                pull_and_verify(rep, *rec, dst, dmemh, rs[r].buf);
                poll_until(rs[r].ctx.fired);
                dereg(receiver(), dmemh);
                dereg(sender(), rs[r].memh);
            }
        }
    }
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/*
 * A receive that would match a rendezvous UCP has yet to be told of is refused,
 * so that UCP keeps it in software and matches it to that rendezvous when it is
 * reported (the rendezvous is out of the NIC's list already: a receive posted
 * there would take a later message, and UCP would then match the report to it).
 *
 * The rendezvous is held by handing its arrival event to the handler by hand,
 * without the sender's announce, which the interface then waits for. The
 * receiver's other events are dropped, nothing here goes on to report it.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, receive_matching_a_held_rendezvous_is_refused)
{
    static const uct_tag_t TAG     = 0xBEEF1234000000A5ULL;
    static const size_t    PAY_LEN = 4096;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h         sep    = sender().ep(0);
    uct_cxi_iface_t *riface = ucs_derived_of(receiver().iface(), uct_cxi_iface_t);

    unexp_rndv_send rs;
    rs.buf.assign(PAY_LEN, 0x3C);
    rs.memh = reg(sender(), rs.buf.data(), PAY_LEN);
    init_rndv_send_ctx(rs.ctx);

    uct_iov_t siov;
    siov.buffer = rs.buf.data();
    siov.length = PAY_LEN;
    siov.memh   = rs.memh;
    siov.stride = 0;
    siov.count  = 1;
    std::vector<uint8_t> hdr = pack_rndv_hdr(0x77, 0x1000, 3);
    void *rop = uct_ep_tag_rndv_zcopy(sep, TAG, hdr.data(), hdr.size(), &siov, 1,
                                      0, &rs.ctx.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(rop));

    usleep(200000); /* it has landed, the receiver has not looked */

    union c_event arrival;
    bool          found    = false;
    ucs_time_t    deadline = ucs_get_time() + ucs_time_from_sec(2.0);
    while (!found && (ucs_get_time() < deadline)) {
        const union c_event *ev;
        while ((ev = cxi_eq_get_event(riface->rx_eq.evtq)) != NULL) {
            if ((ev->hdr.event_type == C_EVENT_PUT) &&
                (ev->tgt_long.ptlte_index == riface->tag.pte->ptn) &&
                (ev->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) &&
                ev->tgt_long.rendezvous) {
                arrival = *ev;
                found   = true;
            }
        }
        cxi_eq_ack_events(riface->rx_eq.evtq);
    }
    ASSERT_TRUE(found) << "the rendezvous never arrived";

    /* Without its announce, the rendezvous is held. */
    uct_cxi_iface_tag_handle_ovf_arrival(riface, &arrival);
    ASSERT_EQ(1u, riface->tag.unexp_held);
    EXPECT_TRUE(m_ctx.records.empty());

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
    uct_iov_t            iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    struct recv_t {
        uct_cxi_tag_recv_ctx ctx;
        uct_tag_t            tag, mask;
        ucs_status_t         expect;
    } recvs[] = {
        {{}, TAG,               UCS_MASK(64),     UCS_ERR_NO_RESOURCE}, /* exact */
        {{}, TAG ^ 0xFF00,      0xFFFFFFFF000000FFULL,
                                                  UCS_ERR_NO_RESOURCE}, /* masked */
        {{}, 0,                 0,                UCS_ERR_NO_RESOURCE}, /* any */
        {{}, TAG ^ 0x10,        UCS_MASK(64),     UCS_OK},              /* other tag */
        {{}, TAG ^ 0x1000000000, 0xFFFFFFFF000000FFULL,
                                                  UCS_OK}               /* other tag, masked */
    };

    for (recv_t &r : recvs) {
        memset(&r.ctx, 0, sizeof(r.ctx));
        r.ctx.super.tag_consumed_cb = uct_cxi_tag_consumed_cb;
        r.ctx.super.completed_cb    = uct_cxi_tag_completed_cb;
        EXPECT_EQ(r.expect,
                  uct_iface_tag_recv_zcopy(receiver().iface(), r.tag, r.mask,
                                           &iov, 1, &r.ctx.super))
                << "tag 0x" << std::hex << r.tag << " mask 0x" << r.mask;
        if (r.expect == UCS_OK) {
            ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                    &r.ctx.super, 1));
        }
    }

    ASSERT_UCS_OK(uct_ep_tag_rndv_cancel(sep, rop));
    dereg(receiver(), rx_memh);
    dereg(sender(), rs.memh);
}


/*
 * Many unexpected rendezvous at once, all with the same tag. Each is reported
 * only after its own address read, and the reads need not finish in the order
 * they were posted: they must still be reported in the order sent, and each
 * with the right source address (every payload is checked through its own
 * pull).
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, many_rendezvous_reported_in_send_order)
{
    static const unsigned N       = 64;
    static const size_t   PAY_LEN = 2048;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    std::vector<unexp_rndv_send *> sends;
    for (unsigned i = 0; i < N; i++) {
        unexp_rndv_send *rs = new unexp_rndv_send();
        rs->buf.assign(PAY_LEN, (uint8_t)(i + 1));
        rs->memh = reg(sender(), rs->buf.data(), PAY_LEN);
        init_rndv_send_ctx(rs->ctx);

        uct_iov_t siov;
        siov.buffer = rs->buf.data();
        siov.length = PAY_LEN;
        siov.memh   = rs->memh;
        siov.stride = 0;
        siov.count  = 1;
        std::vector<uint8_t> hdr = pack_rndv_hdr(0x88, i, 5);

        ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                sep, 0xC0DE000000000000ULL, hdr.data(), hdr.size(), &siov,
                1, 0, &rs->ctx.super)));
        sends.push_back(rs);
    }

    poll_until_count(N);
    ASSERT_EQ(N, m_ctx.records.size());
    for (unsigned i = 0; i < N; i++) {
        EXPECT_EQ(i, m_ctx.records[i].req_id) << "reported out of send order";
        EXPECT_EQ(0xC0DE000000000000ULL, m_ctx.records[i].tag);
    }

    for (unsigned i = 0; i < N; i++) {
        std::vector<uint8_t> dst(PAY_LEN, 0);
        uct_mem_h            dmemh = reg(receiver(), dst.data(), PAY_LEN);
        pull_and_verify(rep, m_ctx.records[i], dst, dmemh, sends[i]->buf);
        poll_until(sends[i]->ctx.fired);
        dereg(receiver(), dmemh);
    }
    for (unsigned i = 0; i < N; i++) {
        dereg(sender(), sends[i]->memh);
        delete sends[i];
    }
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}


/*
 * A receive posted at about the time an unexpected rendezvous arrives. The
 * message is reported to UCP (owned: our SEARCH_AND_DELETE took it) or goes
 * to the receive (lost: the receive's append matched it first, possibly
 * after its address read was already posted), and never both. The receive is
 * posted a varying number of progress rounds after the send, so the append
 * lands at every point from before the message arrives to well after it was
 * reported, including the windows where the address read is in flight.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, rendezvous_vs_posted_receive)
{
    static const unsigned ITERS   = 200;
    static const unsigned MAX_LAG = 50;
    static const size_t   PAY_LEN = 4096;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    unsigned to_receive = 0, to_report = 0, reported_first = 0;

    for (unsigned i = 0; i < ITERS; i++) {
        const uct_tag_t tag  = 0xBEEF000000000000ULL | i;
        const uint8_t   fill = (uint8_t)(i + 1);

        auto reported = [&]() -> const rndv_arrival_record * {
            for (size_t k = 0; k < m_ctx.records.size(); k++) {
                if (m_ctx.records[k].tag == tag) {
                    return &m_ctx.records[k];
                }
            }
            return NULL;
        };

        std::vector<uint8_t> tx_buf(PAY_LEN, fill);
        uct_mem_h tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
        uct_cxi_rndv_send_ctx sctx;
        init_rndv_send_ctx(sctx);

        uct_iov_t siov;
        siov.buffer = tx_buf.data();
        siov.length = PAY_LEN;
        siov.memh   = tx_memh;
        siov.stride = 0;
        siov.count  = 1;
        std::vector<uint8_t> hdr = pack_rndv_hdr(0x99, i, 2);
        ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                sep, tag, hdr.data(), hdr.size(), &siov, 1, 0, &sctx.super)));

        for (unsigned lag = 0; lag < (i % MAX_LAG); lag++) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }

        std::vector<uint8_t> rx_buf(PAY_LEN, 0);
        uct_mem_h rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
        uct_cxi_tag_recv_ctx rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.super.tag_consumed_cb = uct_cxi_tag_consumed_cb;
        rctx.super.completed_cb    = uct_cxi_tag_completed_cb;

        bool posted = false;
        if (reported() != NULL) {
            reported_first++;
        } else {
            uct_iov_t riov;
            riov.buffer = rx_buf.data();
            riov.length = PAY_LEN;
            riov.memh   = rx_memh;
            riov.stride = 0;
            riov.count  = 1;
            /* Refused while the rendezvous is held for its address read: UCP
             * would match the receive to it in software when reported. */
            ucs_status_t status = uct_iface_tag_recv_zcopy(receiver().iface(),
                                                           tag, UCS_MASK(64),
                                                           &riov, 1,
                                                           &rctx.super);
            ASSERT_TRUE((status == UCS_OK) || (status == UCS_ERR_NO_RESOURCE))
                    << ucs_status_string(status);
            posted = (status == UCS_OK);
        }

        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        while (!rctx.completed && (reported() == NULL) &&
               (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_TRUE(rctx.completed || (reported() != NULL))
                << "iteration " << i << ": the message vanished";

        /* Time for a second, wrong, outcome to show up. */
        ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.02);
        while (ucs_get_time() < settle) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }

        const rndv_arrival_record *rec = reported();
        if (rctx.completed) {
            to_receive++;
            EXPECT_TRUE(rec == NULL)
                    << "iteration " << i << ": delivered to the receive AND "
                       "reported to UCP";
            EXPECT_EQ(UCS_OK, rctx.status);
            for (size_t b = 0; b < PAY_LEN; b++) {
                ASSERT_EQ(fill, rx_buf[b]) << "iteration " << i << " byte "
                                           << b;
            }
        } else {
            to_report++;
            ASSERT_TRUE(rec != NULL);
            EXPECT_EQ(i, rec->req_id);
            if (posted) {
                ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                        &rctx.super, 1));
            }
            std::vector<uint8_t> dst(PAY_LEN, 0);
            uct_mem_h dmemh = reg(receiver(), dst.data(), PAY_LEN);
            pull_and_verify(rep, *rec, dst, dmemh, tx_buf);
            dereg(receiver(), dmemh);
        }

        poll_until(sctx.fired);
        dereg(receiver(), rx_memh);
        dereg(sender(), tx_memh);
    }

    UCS_TEST_MESSAGE << to_receive << " went to the receive, " << to_report
                     << " were reported (" << reported_first
                     << " before the receive was posted)";
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}


/*
 * An eager message held behind a rendezvous with its tag has to be let go
 * when the rendezvous is not to be reported after all, because a receive
 * posted in the meantime took it. A rendezvous and an eager message with the
 * same tag are sent back to back, and a receive for the tag is posted a
 * varying time later. The receive takes one of the two at most; every other
 * must be reported, once, and in the order sent if both are.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, eager_behind_rendezvous_taken_by_receive)
{
    static const unsigned ITERS   = 100;
    static const unsigned MAX_LAG = 50;
    static const size_t   PAY_LEN = 4096;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    for (unsigned i = 0; i < ITERS; i++) {
        const uct_tag_t tag    = 0xCAFE000000000000ULL | i;
        const size_t    before = m_ctx.order.size();
        const size_t    rbefore = m_ctx.records.size();

        std::vector<uint8_t> tx_buf(PAY_LEN, (uint8_t)(i + 1));
        uct_mem_h tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
        uct_cxi_rndv_send_ctx sctx;
        init_rndv_send_ctx(sctx);

        uct_iov_t siov;
        siov.buffer = tx_buf.data();
        siov.length = PAY_LEN;
        siov.memh   = tx_memh;
        siov.stride = 0;
        siov.count  = 1;
        std::vector<uint8_t> hdr = pack_rndv_hdr(0x99, i, 2);
        ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                sep, tag, hdr.data(), hdr.size(), &siov, 1, 0, &sctx.super)));
        uint64_t marker = 0xE000 + i;
        ASSERT_UCS_OK(uct_ep_tag_eager_short(sep, tag, &marker,
                                             sizeof(marker)));

        for (unsigned lag = 0; lag < (i % MAX_LAG); lag++) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }

        std::vector<uint8_t> rx_buf(PAY_LEN, 0);
        uct_mem_h rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
        uct_cxi_tag_recv_ctx rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.super.tag_consumed_cb = uct_cxi_tag_consumed_cb;
        rctx.super.completed_cb    = uct_cxi_tag_completed_cb;
        uct_iov_t riov;
        riov.buffer = rx_buf.data();
        riov.length = PAY_LEN;
        riov.memh   = rx_memh;
        riov.stride = 0;
        riov.count  = 1;
        /* Refused while the rendezvous is held (UCP would match it in
         * software): then both messages are reported. */
        ucs_status_t post_status = uct_iface_tag_recv_zcopy(receiver().iface(),
                                                            tag, UCS_MASK(64),
                                                            &riov, 1,
                                                            &rctx.super);
        ASSERT_TRUE((post_status == UCS_OK) ||
                    (post_status == UCS_ERR_NO_RESOURCE))
                << ucs_status_string(post_status);
        const bool posted = (post_status == UCS_OK);

        /* Two messages: the receive takes one or none, the rest is reported. */
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        while (((m_ctx.order.size() - before) + (rctx.completed ? 1 : 0) < 2) &&
               (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.02);
        while (ucs_get_time() < settle) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        const size_t reports = m_ctx.order.size() - before;
        ASSERT_EQ(2u, reports + (rctx.completed ? 1 : 0))
                << "iteration " << i << ": " << reports << " reported, "
                << "receive " << (rctx.completed ? "completed" : "pending");

        if (posted && !rctx.completed) {
            ASSERT_UCS_OK(uct_iface_tag_recv_cancel(receiver().iface(),
                                                    &rctx.super, 1));
        }
        if (reports == 2) {
            EXPECT_TRUE(m_ctx.order[before].rndv)
                    << "iteration " << i << ": the eager message was "
                       "reported ahead of the rendezvous sent before it";
        }

        /* Whatever was reported as a rendezvous is pulled and checked; if it
         * was the receive's instead, check what it got. */
        if (m_ctx.records.size() > rbefore) {
            std::vector<uint8_t> dst(PAY_LEN, 0);
            uct_mem_h dmemh = reg(receiver(), dst.data(), PAY_LEN);
            pull_and_verify(rep, m_ctx.records[rbefore], dst, dmemh, tx_buf);
            dereg(receiver(), dmemh);
        } else {
            ASSERT_TRUE(rctx.completed);
            EXPECT_EQ(PAY_LEN, rctx.length) << "iteration " << i;
            EXPECT_EQ(tx_buf, rx_buf) << "iteration " << i;
        }

        poll_until(sctx.fired);
        dereg(receiver(), rx_memh);
        dereg(sender(), tx_memh);
    }
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/*
 * A SEARCH_AND_DELETE deletes the oldest unexpected entry with its tag, which
 * is not always the arrival it was issued for, and what it finds must be
 * handled as what it is: an eager message as eager, a rendezvous as
 * rendezvous, whichever kind of arrival the command was issued for.
 *
 * That is made certain here, rather than left to a race: an eager message and
 * a rendezvous with the same tag are let land in the overflow list while the
 * receiver does not progress, and a receive for the tag is posted. The
 * hardware gives it the oldest of the two. Only then does the receiver
 * progress: it issues a SEARCH_AND_DELETE for each arrival, and the first, the
 * one for the arrival the receive took, finds the other message, of the other
 * kind. That one must be reported to UCP once, intact, and the receive must
 * have got the other one intact. Both send orders are tried.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, search_delete_finds_the_other_kind)
{
    static const unsigned ROUNDS  = 10;
    static const size_t   PAY_LEN = 4096;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    for (unsigned rndv_first = 0; rndv_first < 2; rndv_first++) {
        for (unsigned i = 0; i < ROUNDS; i++) {
            const uct_tag_t tag     = 0xD00D000000000000ULL |
                                      (rndv_first << 16) | i;
            const uint64_t  marker  = 0xE000 + i;
            const size_t    before  = m_ctx.order.size();
            const size_t    rbefore = m_ctx.records.size();
            const char     *what    = rndv_first ? "rendezvous first" :
                                                   "eager first";

            std::vector<uint8_t> tx_buf(PAY_LEN, (uint8_t)(i + 1));
            uct_mem_h tx_memh = reg(sender(), tx_buf.data(), PAY_LEN);
            uct_cxi_rndv_send_ctx sctx;
            init_rndv_send_ctx(sctx);

            uct_iov_t siov;
            siov.buffer = tx_buf.data();
            siov.length = PAY_LEN;
            siov.memh   = tx_memh;
            siov.stride = 0;
            siov.count  = 1;
            std::vector<uint8_t> hdr = pack_rndv_hdr(0x99, i, 2);

            for (unsigned k = 0; k < 2; k++) {
                if (k == rndv_first) {
                    ASSERT_UCS_OK(uct_ep_tag_eager_short(sep, tag, &marker,
                                                         sizeof(marker)));
                } else {
                    ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                            sep, tag, hdr.data(), hdr.size(), &siov, 1, 0,
                            &sctx.super)));
                }
            }

            /* Both land while only the sender progresses (for its own
             * acknowledgements): the receiver has not seen either yet. */
            ucs_time_t landed = ucs_get_time() + ucs_time_from_sec(0.1);
            while (ucs_get_time() < landed) {
                uct_iface_progress(sender().iface());
            }

            std::vector<uint8_t> rx_buf(PAY_LEN, 0);
            uct_mem_h rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
            uct_cxi_tag_recv_ctx rctx;
            memset(&rctx, 0, sizeof(rctx));
            rctx.super.tag_consumed_cb = uct_cxi_tag_consumed_cb;
            rctx.super.completed_cb    = uct_cxi_tag_completed_cb;
            uct_iov_t riov;
            riov.buffer = rx_buf.data();
            riov.length = PAY_LEN;
            riov.memh   = rx_memh;
            riov.stride = 0;
            riov.count  = 1;
            ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), tag,
                                                   UCS_MASK(64), &riov, 1,
                                                   &rctx.super));
            ucs_time_t appended = ucs_get_time() + ucs_time_from_sec(0.1);
            while (ucs_get_time() < appended) {
                uct_iface_progress(sender().iface());
            }

            ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
            while ((m_ctx.order.size() == before) &&
                   (ucs_get_time() < deadline)) {
                uct_iface_progress(sender().iface());
                uct_iface_progress(receiver().iface());
            }
            ucs_time_t settle = ucs_get_time() + ucs_time_from_sec(0.02);
            while (ucs_get_time() < settle) {
                uct_iface_progress(sender().iface());
                uct_iface_progress(receiver().iface());
            }

            ASSERT_TRUE(rctx.completed) << what << " round " << i
                    << ": the receive got neither message";
            ASSERT_EQ(before + 1, m_ctx.order.size())
                    << what << " round " << i << ": the other message was "
                    << "reported " << (m_ctx.order.size() - before)
                    << " times";
            const unexp_arrival &a = m_ctx.order[before];

            if (a.rndv) {
                /* The receive got the eager message. */
                EXPECT_EQ(sizeof(marker), rctx.length) << what << " " << i;
                uint64_t got = 0;
                memcpy(&got, rx_buf.data(), sizeof(got));
                EXPECT_EQ(marker, got) << what << " round " << i;

                ASSERT_EQ(rbefore + 1, m_ctx.records.size());
                std::vector<uint8_t> dst(PAY_LEN, 0);
                uct_mem_h dmemh = reg(receiver(), dst.data(), PAY_LEN);
                pull_and_verify(rep, m_ctx.records[rbefore], dst, dmemh,
                                tx_buf);
                dereg(receiver(), dmemh);
            } else {
                /* The receive got the rendezvous. */
                EXPECT_EQ(marker, a.id) << what << " round " << i
                        << ": eager message reported with the wrong data";
                EXPECT_EQ(rbefore, m_ctx.records.size());
                EXPECT_EQ(PAY_LEN, rctx.length) << what << " " << i;
                EXPECT_EQ(tx_buf, rx_buf) << what << " round " << i;
            }

            poll_until(sctx.fired);
            dereg(receiver(), rx_memh);
            dereg(sender(), tx_memh);
        }
    }
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

/*
 * Several streams at once: rendezvous with a few different tags sent
 * interleaved, an eager message among them for each tag. Each stream has to be
 * reported in the order it was sent (its own tag, same sender), whatever the
 * others do, every message once, and the pull of each has to give its data.
 */
UCS_TEST_P(test_cxi_tag_rndv_unexp, many_streams_each_in_order)
{
    static const unsigned TAGS    = 8;
    static const unsigned PER_TAG = 8;
    static const size_t   PAY_LEN = 1024;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(receiver(), 0, sender());
    uct_ep_h sep = sender().ep(0);
    uct_ep_h rep = receiver().ep(0);

    std::vector<unexp_rndv_send *> sends;
    for (unsigned n = 0; n < PER_TAG; n++) {
        for (unsigned t = 0; t < TAGS; t++) {
            const uct_tag_t tag = 0xA5A5000000000000ULL | t;
            unexp_rndv_send *rs = new unexp_rndv_send();
            rs->buf.assign(PAY_LEN, (uint8_t)(t * PER_TAG + n + 1));
            rs->memh = reg(sender(), rs->buf.data(), PAY_LEN);
            init_rndv_send_ctx(rs->ctx);

            uct_iov_t siov;
            siov.buffer = rs->buf.data();
            siov.length = PAY_LEN;
            siov.memh   = rs->memh;
            siov.stride = 0;
            siov.count  = 1;
            /* req_id: the tag and the position in its stream */
            std::vector<uint8_t> hdr = pack_rndv_hdr(0x66, t * 1000 + n, 4);
            ASSERT_FALSE(UCS_PTR_IS_ERR(uct_ep_tag_rndv_zcopy(
                    sep, tag, hdr.data(), hdr.size(), &siov, 1, 0,
                    &rs->ctx.super)));
            sends.push_back(rs);
        }
    }

    poll_until_count(TAGS * PER_TAG);
    ASSERT_EQ(TAGS * PER_TAG, m_ctx.records.size());

    unsigned next[TAGS] = {};
    for (size_t i = 0; i < m_ctx.records.size(); i++) {
        const unsigned t = m_ctx.records[i].tag & 0xff;
        ASSERT_LT(t, TAGS);
        EXPECT_EQ(t * 1000 + next[t], m_ctx.records[i].req_id)
                << "tag " << t << " reported out of its stream's order";
        next[t]++;
    }

    for (size_t i = 0; i < m_ctx.records.size(); i++) {
        const unsigned t = m_ctx.records[i].tag & 0xff;
        const unsigned n = m_ctx.records[i].req_id % 1000;
        std::vector<uint8_t> dst(PAY_LEN, 0);
        uct_mem_h            dmemh = reg(receiver(), dst.data(), PAY_LEN);
        pull_and_verify(rep, m_ctx.records[i], dst, dmemh,
                        sends[n * TAGS + t]->buf);
        dereg(receiver(), dmemh);
    }
    for (size_t i = 0; i < sends.size(); i++) {
        poll_until(sends[i]->ctx.fired);
        dereg(sender(), sends[i]->memh);
        delete sends[i];
    }
    flush_ep(sender(), sep);
#ifndef UCT_CXI_DISABLE_FC
    cxi_expect_conserved(sender(), receiver());
#endif
}

_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_rndv_unexp, cxi)

/**
 * Unexpected rendezvous from two different senders to one receiver.
 *
 * Each sender announces its own {ep_id, md_index} once; the receiver must
 * rebuild every arrival's header from the announce of the sender that sent
 * it. That needs the receiver to tell senders apart, which it does by the
 * initiator field of the arrival event -- so this fails if events do not
 * carry the sender's identity (all senders then look like one, and the last
 * announce overwrites the others).
 *
 * Everything is let to land before the receiver looks, so both announces are
 * processed before either arrival is.
 */
class test_cxi_tag_rndv_unexp_two_senders : public test_cxi_tag_rndv_unexp {
protected:
    void init() override
    {
        test_cxi_tag_rndv_unexp::init();
        m_entities.push_back(uct_test::create_entity(
                0, NULL, unexp_rndv_eager_cb, unexp_rndv_cb, &m_ctx,
                &m_ctx)); /* second sender */
    }

    entity &sender2() { return m_entities.at(2); }
};

UCS_TEST_P(test_cxi_tag_rndv_unexp_two_senders, each_sender_keeps_its_header)
{
    static const size_t   PAY_LEN = 256;
    static const uint64_t TAG_A   = 0xA000000000000001ULL;
    static const uint64_t TAG_B   = 0xB000000000000002ULL;
    static const uint64_t EP_ID_A = 0xAAAA0000AAAA0001ULL;
    static const uint64_t EP_ID_B = 0xBBBB0000BBBB0002ULL;
    static const uint64_t REQ_A   = 0x1111111111111111ULL;
    static const uint64_t REQ_B   = 0x2222222222222222ULL;
    static const uint8_t  MD_A    = 3;
    static const uint8_t  MD_B    = 9;

    cxi_connect(sender(), 0, receiver());
    cxi_connect(sender2(), 0, receiver());

    std::vector<uint8_t> tx_a(PAY_LEN, 0xAA), tx_b(PAY_LEN, 0xBB);
    uct_mem_h            memh_a = reg(sender(), tx_a.data(), PAY_LEN);
    uct_mem_h            memh_b = reg(sender2(), tx_b.data(), PAY_LEN);
    uct_cxi_rndv_send_ctx sctx_a, sctx_b;
    init_rndv_send_ctx(sctx_a);
    init_rndv_send_ctx(sctx_b);

    std::vector<uint8_t> hdr_a = pack_rndv_hdr(EP_ID_A, REQ_A, MD_A);
    std::vector<uint8_t> hdr_b = pack_rndv_hdr(EP_ID_B, REQ_B, MD_B);
    uct_iov_t iov_a = {tx_a.data(), PAY_LEN, memh_a, 0, 1};
    uct_iov_t iov_b = {tx_b.data(), PAY_LEN, memh_b, 0, 1};

    ucs_status_ptr_t op_a = uct_ep_tag_rndv_zcopy(sender().ep(0), TAG_A,
                                                  hdr_a.data(), hdr_a.size(),
                                                  &iov_a, 1, 0, &sctx_a.super);
    ucs_status_ptr_t op_b = uct_ep_tag_rndv_zcopy(sender2().ep(0), TAG_B,
                                                  hdr_b.data(), hdr_b.size(),
                                                  &iov_b, 1, 0, &sctx_b.super);
    ASSERT_FALSE(UCS_PTR_IS_ERR(op_a));
    ASSERT_FALSE(UCS_PTR_IS_ERR(op_b));

    /* Both announces and both arrivals land before the receiver looks. */
    usleep(200000);

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    while ((m_ctx.records.size() < 2) && (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(sender2().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_EQ(2u, m_ctx.records.size());

    for (const rndv_arrival_record &rec : m_ctx.records) {
        const bool is_a = (rec.tag == TAG_A);
        ASSERT_TRUE(is_a || (rec.tag == TAG_B)) << "unknown tag 0x" << std::hex
                                                << rec.tag;
        EXPECT_EQ(is_a ? EP_ID_A : EP_ID_B, rec.ep_id)
                << "arrival for tag 0x" << std::hex << rec.tag
                << " was given another sender's ep_id";
        EXPECT_EQ(is_a ? MD_A : MD_B, rec.md_index)
                << "arrival for tag 0x" << std::hex << rec.tag
                << " was given another sender's md_index";
        EXPECT_EQ(is_a ? REQ_A : REQ_B, rec.req_id);
        uct_rkey_release(m_ctx.component, &rec.rkey_bundle);
    }

    /* Nothing pulls the data: withdraw the sends. */
    uct_ep_tag_rndv_cancel(sender().ep(0), op_a);
    uct_ep_tag_rndv_cancel(sender2().ep(0), op_b);
    flush_ep(sender(), sender().ep(0));
    flush_ep(sender2(), sender2().ep(0));
    dereg(sender(), memh_a);
    dereg(sender2(), memh_b);
}

_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_rndv_unexp_two_senders, cxi)

