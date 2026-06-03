/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT RMA unit tests — ep_put/get_{short,bcopy,zcopy}.
 *
 * All tests use two entity instances (sender at index 0, receiver at index 1)
 * on the same transport.  On single-node allocations both entities share one
 * physical NIC and traffic travels over the intra-NIC loopback path.
 *
 * ep_put_zcopy tests
 * ──────────────────
 * The sender registers src, the receiver registers dst.  The sender posts a
 * PUT targeting the receiver's dst via the receiver's rkey.  On C_EVENT_ACK
 * the NIC has committed the DMA write; src and dst are compared.
 *
 * ep_get_zcopy tests
 * ──────────────────
 * The receiver fills src with a known pattern and registers it.  The sender
 * registers dst (initially zero).  The sender posts a GET from the receiver's
 * src into the sender's dst.  On C_EVENT_REPLY the NIC has written remote data
 * into dst; dst is compared against the original pattern.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_rma.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>


/* -------------------------------------------------------------------------
 * Fixture
 * -------------------------------------------------------------------------
 */

/**
 * test_cxi_rma — data-movement fixture.
 *
 * Inherits the two-entity setup and all memory helpers from test_cxi_rma_base.
 */
class test_cxi_rma : public test_cxi_rma_base {};


/* -------------------------------------------------------------------------
 * ep_put_zcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Post a single ep_put_zcopy and verify the data arrives in the receiver's
 * buffer.
 *
 * src (sender side) is filled with 0xAB; dst (receiver side) starts zeroed.
 * After flush dst must equal src.
 */
UCS_TEST_P(test_cxi_rma, put_zcopy_single)
{
    static const size_t  SIZE = 4 * UCS_KBYTE;

    std::vector<uint8_t> src(SIZE, 0xAB);
    std::vector<uint8_t> dst(SIZE, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(sender(),   src.data(), SIZE);
    uct_mem_h dst_memh = reg(receiver(), dst.data(), SIZE);

    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    uct_iov_t iov;
    iov.buffer = src.data();
    iov.length = SIZE;
    iov.memh   = src_memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t status = uct_ep_put_zcopy(ep, &iov, 1,
                                            (uint64_t)(uintptr_t)dst.data(),
                                            rkey_bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, (int)status)
            << "ep_put_zcopy must return UCS_INPROGRESS";

    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "PUT data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(sender(),   src_memh);
    dereg(receiver(), dst_memh);
}

/**
 * Post a single ep_put_short (inline IDC) and verify the data arrives.
 *
 * A 64-byte payload (well within the 224 B IDC limit) is written inline
 * into the NIC command — no local mem_reg needed for the source.  The
 * trailing DMA fence ensures ep_flush waits for ordered completion.
 */
UCS_TEST_P(test_cxi_rma, put_short_single)
{
    static const size_t  SIZE = 64;

    std::vector<uint8_t> src(SIZE, 0x5A);
    std::vector<uint8_t> dst(SIZE, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Only the destination buffer needs registration (remote target). */
    uct_mem_h dst_memh = reg(receiver(), dst.data(), SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    /* ep_put_short takes a plain pointer — no iov, no local memh. */
    ucs_status_t status = uct_ep_put_short(ep,
                                            src.data(), (unsigned)SIZE,
                                            (uint64_t)(uintptr_t)dst.data(),
                                            rkey_bundle.rkey);
    ASSERT_EQ(UCS_OK, (int)status) << "ep_put_short must return UCS_OK";

    /* Flush waits for the fence DMA ACK — guarantees remote visibility. */
    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "put_short data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), dst_memh);
}

/**
 * Post a single ep_get_short and verify the remote data arrives in the
 * caller's buffer.
 *
 * src (receiver side) holds 0xC3 — this is the remote source.  The sender
 * calls ep_get_short; the implementation spins until C_EVENT_REPLY then
 * copies the scratch buffer into `dst`.
 *
 * Only the remote source needs registration; the local destination is the
 * iface scratch buffer (already registered at iface_open).
 */
UCS_TEST_P(test_cxi_rma, get_short_single)
{
    static const size_t  SIZE = 64;

    std::vector<uint8_t> src(SIZE, 0xC3); /* remote source — on receiver */
    std::vector<uint8_t> dst(SIZE, 0x00); /* local result  — filled by get_short */

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Only the remote source needs registration. */
    uct_mem_h src_memh = reg(receiver(), src.data(), SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    /* ep_get_short blocks until C_EVENT_REPLY and copies into dst directly. */
    ucs_status_t status = uct_ep_get_short(ep,
                                            dst.data(), (unsigned)SIZE,
                                            (uint64_t)(uintptr_t)src.data(),
                                            rkey_bundle.rkey);
    ASSERT_EQ(UCS_OK, (int)status) << "ep_get_short must return UCS_OK";

    EXPECT_EQ(src, dst) << "get_short data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
}

/**
 * Post N sequential ep_get_short calls from distinct regions of the
 * receiver's buffer and verify each result independently.
 *
 * Since get_short is synchronous (spins until complete), each call must
 * return the correct data before the next is issued.
 */
UCS_TEST_P(test_cxi_rma, get_short_multiple)
{
    static const size_t STRIDE = 16;
    static const int    N_OPS  = 8;
    static const size_t TOTAL  = (size_t)N_OPS * STRIDE;

    /* Each stride holds a distinct fill byte so mis-routing is detectable. */
    std::vector<uint8_t> src(TOTAL);
    for (int i = 0; i < N_OPS; ++i) {
        std::fill(src.begin() + (size_t)i * STRIDE,
                  src.begin() + (size_t)(i + 1) * STRIDE,
                  (uint8_t)(0x10 + i));
    }

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src.data(), TOTAL);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), TOTAL);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    for (int i = 0; i < N_OPS; ++i) {
        std::vector<uint8_t> dst(STRIDE, 0x00);

        ucs_status_t status =
                uct_ep_get_short(ep,
                                 dst.data(), (unsigned)STRIDE,
                                 (uint64_t)(uintptr_t)(src.data() +
                                                       (size_t)i * STRIDE),
                                 rkey_bundle.rkey);
        ASSERT_EQ(UCS_OK, (int)status) << "get_short op " << i;

        std::vector<uint8_t> expected(STRIDE, (uint8_t)(0x10 + i));
        EXPECT_EQ(expected, dst) << "get_short data mismatch at stride " << i;
    }

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
}

/**
 * Post N back-to-back ep_put_zcopy operations targeting distinct 4 KB regions,
 * then flush and verify all regions were written correctly.
 */
UCS_TEST_P(test_cxi_rma, put_zcopy_multiple)
{
    static const size_t  STRIDE = 4 * UCS_KBYTE;
    static const int     N_OPS  = 8;
    static const size_t  TOTAL  = (size_t)N_OPS * STRIDE;

    std::vector<uint8_t> src(TOTAL, 0xCD);
    std::vector<uint8_t> dst(TOTAL, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(sender(),   src.data(), TOTAL);
    uct_mem_h dst_memh = reg(receiver(), dst.data(), TOTAL);

    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst.data(), TOTAL);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    for (int i = 0; i < N_OPS; ++i) {
        uct_iov_t iov;
        iov.buffer = src.data() + (size_t)i * STRIDE;
        iov.length = STRIDE;
        iov.memh   = src_memh;
        iov.stride = 0;
        iov.count  = 1;

        ucs_status_t status =
                uct_ep_put_zcopy(ep, &iov, 1,
                                 (uint64_t)(uintptr_t)(dst.data() +
                                                       (size_t)i * STRIDE),
                                 rkey_bundle.rkey, NULL);
        ASSERT_EQ(UCS_INPROGRESS, (int)status) << "PUT op " << i;
    }

    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "PUT data mismatch in put_zcopy_multiple";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(sender(),   src_memh);
    dereg(receiver(), dst_memh);
}


/* -------------------------------------------------------------------------
 * ep_get_zcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Post a single ep_get_zcopy and verify the remote data arrives locally.
 *
 * src (receiver side) is filled with 0xEF and registered as the remote source.
 * dst (sender side) starts zeroed and is registered as the local sink.
 * The sender GETs from the receiver's src into the sender's dst.
 * After C_EVENT_REPLY dst must equal src.
 */
UCS_TEST_P(test_cxi_rma, get_zcopy_single)
{
    static const size_t  SIZE = 4 * UCS_KBYTE;

    std::vector<uint8_t> src(SIZE, 0xEF); /* remote source — on receiver side */
    std::vector<uint8_t> dst(SIZE, 0x00); /* local sink   — on sender side    */

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    /* Register src on the receiver's MD (remote) and dst on the sender's MD (local). */
    uct_mem_h src_memh = reg(receiver(), src.data(), SIZE);
    uct_mem_h dst_memh = reg(sender(),   dst.data(), SIZE);

    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    /* Pack the rkey for the remote source buffer. */
    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    /*
     * iov describes the LOCAL destination buffer (where the NIC will write).
     * remote_addr is the remote source VA.
     */
    uct_iov_t iov;
    iov.buffer = dst.data();
    iov.length = SIZE;
    iov.memh   = dst_memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t status = uct_ep_get_zcopy(ep, &iov, 1,
                                            (uint64_t)(uintptr_t)src.data(),
                                            rkey_bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, (int)status)
            << "ep_get_zcopy must return UCS_INPROGRESS";

    /* Poll until C_EVENT_REPLY arrives and the EP drains. */
    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "GET data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
    dereg(sender(),   dst_memh);
}

/**
 * Post N back-to-back ep_get_zcopy operations from distinct 4 KB regions of
 * the receiver's buffer, flush, and verify all local regions match.
 */
UCS_TEST_P(test_cxi_rma, get_zcopy_multiple)
{
    static const size_t  STRIDE = 4 * UCS_KBYTE;
    static const int     N_OPS  = 8;
    static const size_t  TOTAL  = (size_t)N_OPS * STRIDE;

    /* Each stride gets a distinct fill byte so mis-routing is detectable. */
    std::vector<uint8_t> src(TOTAL);
    std::vector<uint8_t> dst(TOTAL, 0x00);
    for (int i = 0; i < N_OPS; ++i) {
        std::fill(src.begin() + (size_t)i * STRIDE,
                  src.begin() + (size_t)(i + 1) * STRIDE,
                  (uint8_t)(0x10 + i));
    }

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src.data(), TOTAL);
    uct_mem_h dst_memh = reg(sender(),   dst.data(), TOTAL);

    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), TOTAL);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    for (int i = 0; i < N_OPS; ++i) {
        uct_iov_t iov;
        iov.buffer = dst.data() + (size_t)i * STRIDE;
        iov.length = STRIDE;
        iov.memh   = dst_memh;
        iov.stride = 0;
        iov.count  = 1;

        ucs_status_t status =
                uct_ep_get_zcopy(ep, &iov, 1,
                                 (uint64_t)(uintptr_t)(src.data() +
                                                       (size_t)i * STRIDE),
                                 rkey_bundle.rkey, NULL);
        ASSERT_EQ(UCS_INPROGRESS, (int)status) << "GET op " << i;
    }

    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "GET data mismatch in get_zcopy_multiple";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
    dereg(sender(),   dst_memh);
}


/* -------------------------------------------------------------------------
 * ep_put_bcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Post a single ep_put_bcopy and verify the data arrives in the receiver's
 * buffer.
 *
 * pack_cb fills the bounce buffer with 0x5A.  After flush the receiver's
 * dst must be all 0x5A (loopback: same physical NIC, pointer is accessible).
 */
UCS_TEST_P(test_cxi_rma, put_bcopy_single)
{
    static const size_t SIZE = 128;

    std::vector<uint8_t> dst(SIZE, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h dst_memh = reg(receiver(), dst.data(), SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    struct pack_arg { size_t size; uint8_t fill; };
    pack_arg parg = { SIZE, 0x5A };

    /* Non-capturing lambda converts to C function pointer. */
    auto pack_fn = [](void *buf, void *arg) -> size_t {
        pack_arg *pa = static_cast<pack_arg *>(arg);
        memset(buf, pa->fill, pa->size);
        return pa->size;
    };

    ssize_t packed = uct_ep_put_bcopy(ep, pack_fn, &parg,
                                       (uint64_t)(uintptr_t)dst.data(),
                                       rkey_bundle.rkey);
    ASSERT_EQ((ssize_t)SIZE, packed) << "put_bcopy must return bytes packed";

    flush_ep(sender(), ep);

    std::vector<uint8_t> expected(SIZE, 0x5A);
    EXPECT_EQ(expected, dst) << "put_bcopy data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), dst_memh);
}

/**
 * Post N back-to-back ep_put_bcopy operations, each targeting a distinct
 * 512-byte stride with a unique fill pattern, then flush and verify all.
 */
UCS_TEST_P(test_cxi_rma, put_bcopy_multiple)
{
    static const size_t  STRIDE = 512;
    static const int     N_OPS  = 8;
    static const size_t  TOTAL  = (size_t)N_OPS * STRIDE;

    std::vector<uint8_t> dst(TOTAL, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h dst_memh = reg(receiver(), dst.data(), TOTAL);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst.data(), TOTAL);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    struct pack_arg { size_t size; uint8_t fill; };
    auto pack_fn = [](void *buf, void *arg) -> size_t {
        pack_arg *pa = static_cast<pack_arg *>(arg);
        memset(buf, pa->fill, pa->size);
        return pa->size;
    };

    /* Post all N ops before flushing. */
    for (int i = 0; i < N_OPS; ++i) {
        pack_arg parg = { STRIDE, (uint8_t)(0x10 + i) };
        ssize_t packed = uct_ep_put_bcopy(
                ep, pack_fn, &parg,
                (uint64_t)(uintptr_t)(dst.data() + (size_t)i * STRIDE),
                rkey_bundle.rkey);
        ASSERT_EQ((ssize_t)STRIDE, packed) << "put_bcopy op " << i;
    }

    flush_ep(sender(), ep);

    for (int i = 0; i < N_OPS; ++i) {
        std::vector<uint8_t> expected(STRIDE, (uint8_t)(0x10 + i));
        std::vector<uint8_t> got(dst.begin() + (long)((size_t)i * STRIDE),
                                  dst.begin() + (long)((size_t)(i + 1) * STRIDE));
        EXPECT_EQ(expected, got) << "put_bcopy data mismatch at stride " << i;
    }

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), dst_memh);
}


/* -------------------------------------------------------------------------
 * ep_get_bcopy tests
 * -------------------------------------------------------------------------
 */

/**
 * Post a single ep_get_bcopy and verify the remote data is delivered via
 * the unpack callback.
 *
 * src (receiver side) is filled with 0xC3 and registered.  The sender
 * issues a get_bcopy; the transport GETs into its bounce buffer, then calls
 * unpack_cb (which memcpy's to dst) on C_EVENT_REPLY.  After flush dst
 * must equal src.
 */
UCS_TEST_P(test_cxi_rma, get_bcopy_single)
{
    static const size_t SIZE = 128;

    std::vector<uint8_t> src(SIZE, 0xC3); /* remote source — on receiver */
    std::vector<uint8_t> dst(SIZE, 0x00); /* local result  — filled by unpack_cb */

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src.data(), SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    /* Non-capturing lambda: arg = local dst buffer pointer. */
    auto unpack_fn = [](void *arg, const void *src_buf, size_t len) {
        memcpy(arg, src_buf, len);
    };

    ucs_status_t status = uct_ep_get_bcopy(ep,
                                            unpack_fn, dst.data(), SIZE,
                                            (uint64_t)(uintptr_t)src.data(),
                                            rkey_bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, (int)status) << "get_bcopy must return UCS_INPROGRESS";

    /* unpack_cb is called from iface_progress before ep->outstanding drops;
     * flush_ep polls until outstanding == 0, so dst is ready on return. */
    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "get_bcopy data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
}

/**
 * Post N back-to-back ep_get_bcopy operations from distinct strides, each
 * with its own unpack destination, then flush and verify all.
 */
UCS_TEST_P(test_cxi_rma, get_bcopy_multiple)
{
    static const size_t  STRIDE = 64;
    static const int     N_OPS  = 8;
    static const size_t  TOTAL  = (size_t)N_OPS * STRIDE;

    std::vector<uint8_t> src(TOTAL);
    for (int i = 0; i < N_OPS; ++i) {
        std::fill(src.begin() + (size_t)i * STRIDE,
                  src.begin() + (size_t)(i + 1) * STRIDE,
                  (uint8_t)(0x10 + i));
    }

    /* Flat destination buffer; each get_bcopy writes to its own stride. */
    std::vector<uint8_t> dst(TOTAL, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src.data(), TOTAL);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src.data(), TOTAL);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    auto unpack_fn = [](void *arg, const void *src_buf, size_t len) {
        memcpy(arg, src_buf, len);
    };

    for (int i = 0; i < N_OPS; ++i) {
        ucs_status_t status = uct_ep_get_bcopy(
                ep, unpack_fn,
                dst.data() + (size_t)i * STRIDE,  /* arg = per-op dst stride */
                STRIDE,
                (uint64_t)(uintptr_t)(src.data() + (size_t)i * STRIDE),
                rkey_bundle.rkey, NULL);
        ASSERT_EQ(UCS_INPROGRESS, (int)status) << "get_bcopy op " << i;
    }

    flush_ep(sender(), ep);

    EXPECT_EQ(src, dst) << "get_bcopy data mismatch in get_bcopy_multiple";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
}


/* -------------------------------------------------------------------------
 * Non-aligned buffer tests
 *
 * These tests exercise the iova_offset formula with buffers that are NOT
 * at the start of their registered page (offset +7 or +3 within a page).
 *
 * Rationale: cxil_map returns page-aligned .iova and .va fields.
 * iova_offset = cxi_md->iova - cxi_md->va (correct formula).
 * For a buffer at page_base + off:
 *   NIC_IOVA(buf) = iova_offset + buf_VA = page_IOVA + off  ← correct.
 * The old formula (- address instead of - va) would cancel the offset and
 * always resolve to page_IOVA, causing DMA to miss the buffer entirely.
 *
 * backing must be 2*PAGE_SIZE so we can always find a page-aligned address
 * within it regardless of how the allocator aligned the vector.
 * -------------------------------------------------------------------------
 */

/**
 * Returns a pointer `offset` bytes past the first page-aligned address
 * found within `backing`.  `backing` must be >= 2 * page_size bytes.
 */
static uint8_t *nonaligned_ptr(std::vector<uint8_t> &backing, size_t offset)
{
    const size_t    pgsz    = ucs_get_page_size();
    const uintptr_t base    = (uintptr_t)backing.data();
    const uintptr_t aligned = (base + pgsz - 1) & ~(pgsz - 1);
    return reinterpret_cast<uint8_t *>(aligned) + offset;
}

static const size_t NONALIGNED_SIZE   = 64;
static const size_t NONALIGNED_OFFSET = 7;   /* remote buffer at page + 7 */
static const size_t NONALIGNED_OFFSET2 = 3;  /* local  buffer at page + 3 */

/**
 * ep_put_short with a non-page-aligned REMOTE target.
 *
 * Tests the remote_offset formula: rkey->iova + remote_addr.
 * With the correct iova_offset, the NIC writes to page+7, not page+0.
 */
UCS_TEST_P(test_cxi_rma, put_short_remote_nonaligned)
{
    const size_t pgsz = ucs_get_page_size();
    std::vector<uint8_t> backing(2 * pgsz, 0x00);
    uint8_t *dst = nonaligned_ptr(backing, NONALIGNED_OFFSET);

    std::vector<uint8_t> src(NONALIGNED_SIZE, 0xD0);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h dst_memh = reg(receiver(), dst, NONALIGNED_SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst, NONALIGNED_SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    ucs_status_t status = uct_ep_put_short(ep, src.data(),
                                            (unsigned)NONALIGNED_SIZE,
                                            (uint64_t)(uintptr_t)dst,
                                            rkey_bundle.rkey);
    ASSERT_EQ(UCS_OK, (int)status);
    flush_ep(sender(), ep);

    std::vector<uint8_t> expected(NONALIGNED_SIZE, 0xD0);
    std::vector<uint8_t> got(dst, dst + NONALIGNED_SIZE);
    EXPECT_EQ(expected, got) << "put_short remote non-aligned data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), dst_memh);
}

/**
 * ep_put_zcopy with non-page-aligned local source (page+7) and
 * non-page-aligned remote destination (page+3).
 *
 * Tests both cmd.local_addr and remote_offset with the corrected formula.
 */
UCS_TEST_P(test_cxi_rma, put_zcopy_nonaligned)
{
    const size_t pgsz = ucs_get_page_size();
    std::vector<uint8_t> src_backing(2 * pgsz, 0x00);
    std::vector<uint8_t> dst_backing(2 * pgsz, 0x00);
    uint8_t *src = nonaligned_ptr(src_backing, NONALIGNED_OFFSET);
    uint8_t *dst = nonaligned_ptr(dst_backing, NONALIGNED_OFFSET2);

    std::fill(src, src + NONALIGNED_SIZE, (uint8_t)0xD1);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(sender(),   src, NONALIGNED_SIZE);
    uct_mem_h dst_memh = reg(receiver(), dst, NONALIGNED_SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), dst_memh, dst, NONALIGNED_SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    uct_iov_t iov;
    iov.buffer = src;
    iov.length = NONALIGNED_SIZE;
    iov.memh   = src_memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t status = uct_ep_put_zcopy(ep, &iov, 1,
                                            (uint64_t)(uintptr_t)dst,
                                            rkey_bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, (int)status);
    flush_ep(sender(), ep);

    std::vector<uint8_t> expected(NONALIGNED_SIZE, 0xD1);
    std::vector<uint8_t> got(dst, dst + NONALIGNED_SIZE);
    EXPECT_EQ(expected, got) << "put_zcopy non-aligned data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(sender(),   src_memh);
    dereg(receiver(), dst_memh);
}

/**
 * ep_get_zcopy with non-page-aligned remote source (page+7) and
 * non-page-aligned local destination (page+3).
 *
 * Tests both remote_offset and cmd.local_addr with the corrected formula.
 */
UCS_TEST_P(test_cxi_rma, get_zcopy_nonaligned)
{
    const size_t pgsz = ucs_get_page_size();
    std::vector<uint8_t> src_backing(2 * pgsz, 0x00);
    std::vector<uint8_t> dst_backing(2 * pgsz, 0x00);
    uint8_t *src = nonaligned_ptr(src_backing, NONALIGNED_OFFSET);
    uint8_t *dst = nonaligned_ptr(dst_backing, NONALIGNED_OFFSET2);

    std::fill(src, src + NONALIGNED_SIZE, (uint8_t)0xD2);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src, NONALIGNED_SIZE);
    uct_mem_h dst_memh = reg(sender(),   dst, NONALIGNED_SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), dst_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src, NONALIGNED_SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    uct_iov_t iov;
    iov.buffer = dst;
    iov.length = NONALIGNED_SIZE;
    iov.memh   = dst_memh;
    iov.stride = 0;
    iov.count  = 1;

    ucs_status_t status = uct_ep_get_zcopy(ep, &iov, 1,
                                            (uint64_t)(uintptr_t)src,
                                            rkey_bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, (int)status);
    flush_ep(sender(), ep);

    std::vector<uint8_t> expected(NONALIGNED_SIZE, 0xD2);
    std::vector<uint8_t> got(dst, dst + NONALIGNED_SIZE);
    EXPECT_EQ(expected, got) << "get_zcopy non-aligned data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
    dereg(sender(),   dst_memh);
}

/**
 * ep_get_short with a non-page-aligned REMOTE source (page+7).
 *
 * Tests the remote_offset formula for short GETs.
 * The local scratch buffer (get_short_buf) is always page-aligned.
 */
UCS_TEST_P(test_cxi_rma, get_short_remote_nonaligned)
{
    const size_t pgsz = ucs_get_page_size();
    std::vector<uint8_t> src_backing(2 * pgsz, 0x00);
    uint8_t *src = nonaligned_ptr(src_backing, NONALIGNED_OFFSET);

    std::fill(src, src + NONALIGNED_SIZE, (uint8_t)0xD3);

    std::vector<uint8_t> dst(NONALIGNED_SIZE, 0x00);

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h src_memh = reg(receiver(), src, NONALIGNED_SIZE);
    ASSERT_NE(static_cast<uct_mem_h>(nullptr), src_memh);

    std::string rkey_buf = pack_rkey(receiver(), src_memh, src, NONALIGNED_SIZE);
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                   rkey_buf.data(), &rkey_bundle));

    ucs_status_t status = uct_ep_get_short(ep, dst.data(),
                                            (unsigned)NONALIGNED_SIZE,
                                            (uint64_t)(uintptr_t)src,
                                            rkey_bundle.rkey);
    ASSERT_EQ(UCS_OK, (int)status);

    std::vector<uint8_t> expected(NONALIGNED_SIZE, 0xD3);
    EXPECT_EQ(expected, dst) << "get_short remote non-aligned data mismatch";

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), src_memh);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_rma, cxi)
