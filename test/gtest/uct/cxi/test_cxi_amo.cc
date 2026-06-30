/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Atomic Memory Operation tests.
 *
 * Each test registers a remote target buffer on the receiver, packs its rkey,
 * then issues atomic operations from the sender.  After flush the target
 * buffer is inspected for the correct result.  Fetch/CSWAP tests also verify
 * the returned old value.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_rma.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <cstring>


class test_cxi_amo : public test_cxi_rma_base {
protected:
    void init() override
    {
        test_cxi_rma_base::init();
        check_caps(UCT_IFACE_FLAG_ATOMIC_DEVICE);
    }

    struct rkey_ctx {
        uct_mem_h          memh;
        uct_rkey_bundle_t  bundle;
    };

    rkey_ctx setup_target(void *buf, size_t len)
    {
        rkey_ctx ctx;
        ctx.memh = reg(receiver(), buf, len);
        std::string packed = pack_rkey(receiver(), ctx.memh, buf, len);
        EXPECT_UCS_OK(uct_rkey_unpack(GetParam()->component,
                                       packed.data(), &ctx.bundle));
        return ctx;
    }

    void teardown_target(rkey_ctx &ctx)
    {
        uct_rkey_release(GetParam()->component, &ctx.bundle);
        dereg(receiver(), ctx.memh);
    }

    void poll_fetch(uct_ep_h ep)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        ucs_status_t st;
        do {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
            st = uct_ep_flush(ep, 0, NULL);
        } while (st == UCS_INPROGRESS && ucs_get_time() < deadline);
        ASSERT_EQ(UCS_OK, st) << "flush timed out";
    }
};


/* -------------------------------------------------------------------------
 * 64-bit post (non-fetching)
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_amo, atomic64_post_add)
{
    uint64_t target = 100;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ASSERT_UCS_OK(uct_ep_atomic64_post(ep, UCT_ATOMIC_OP_ADD, 42,
                  (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    flush_ep(sender(), ep);

    EXPECT_EQ(142ULL, target);
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic64_post_and)
{
    uint64_t target = 0xFF00FF00FF00FF00ULL;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ASSERT_UCS_OK(uct_ep_atomic64_post(ep, UCT_ATOMIC_OP_AND,
                  0x0F0F0F0F0F0F0F0FULL,
                  (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    flush_ep(sender(), ep);

    EXPECT_EQ(0x0F000F000F000F00ULL, target);
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic64_post_or)
{
    uint64_t target = 0x00F000F000F000F0ULL;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ASSERT_UCS_OK(uct_ep_atomic64_post(ep, UCT_ATOMIC_OP_OR,
                  0x000F000F000F000FULL,
                  (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    flush_ep(sender(), ep);

    EXPECT_EQ(0x00FF00FF00FF00FFULL, target);
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic64_post_xor)
{
    uint64_t target = 0xAAAAAAAAAAAAAAAAULL;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ASSERT_UCS_OK(uct_ep_atomic64_post(ep, UCT_ATOMIC_OP_XOR,
                  0xFFFFFFFFFFFFFFFFULL,
                  (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    flush_ep(sender(), ep);

    EXPECT_EQ(0x5555555555555555ULL, target);
    teardown_target(rk);
}


/* -------------------------------------------------------------------------
 * 64-bit fetch
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_amo, atomic64_fetch_add)
{
    uint64_t target = 1000;
    uint64_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic64_fetch(ep, UCT_ATOMIC_OP_ADD, 234,
                      &result, (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(1000ULL, result) << "old value should be 1000";
    EXPECT_EQ(1234ULL, target) << "target should be 1000 + 234";
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic64_fetch_and)
{
    uint64_t target = 0xFFFF0000FFFF0000ULL;
    uint64_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic64_fetch(ep, UCT_ATOMIC_OP_AND,
                      0xFF00FF00FF00FF00ULL, &result,
                      (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(0xFFFF0000FFFF0000ULL, result);
    EXPECT_EQ(0xFF000000FF000000ULL, target);
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic64_fetch_swap)
{
    uint64_t target = 0xDEADBEEFCAFEBABEULL;
    uint64_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic64_fetch(ep, UCT_ATOMIC_OP_SWAP,
                      0x1234567890ABCDEFULL, &result,
                      (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(0xDEADBEEFCAFEBABEULL, result) << "old value mismatch";
    EXPECT_EQ(0x1234567890ABCDEFULL, target) << "target should be new value";
    teardown_target(rk);
}


/* -------------------------------------------------------------------------
 * 64-bit compare-and-swap
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_amo, cswap64_match)
{
    uint64_t target = 42;
    uint64_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic_cswap64(ep, 42, 99,
                      (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, &result, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(42ULL, result) << "old value should be 42";
    EXPECT_EQ(99ULL, target) << "target should be swapped to 99";
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, cswap64_no_match)
{
    uint64_t target = 42;
    uint64_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    /* compare=99 != target=42, so no swap should happen */
    ucs_status_t st = uct_ep_atomic_cswap64(ep, 99, 77,
                      (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, &result, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(42ULL, result) << "old value should be 42";
    EXPECT_EQ(42ULL, target) << "target should NOT have changed";
    teardown_target(rk);
}


/* -------------------------------------------------------------------------
 * 32-bit operations
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_amo, atomic32_post_add)
{
    uint32_t target = 100;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ASSERT_UCS_OK(uct_ep_atomic32_post(ep, UCT_ATOMIC_OP_ADD, 50,
                  (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    flush_ep(sender(), ep);

    EXPECT_EQ(150U, target);
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, atomic32_fetch_add)
{
    uint32_t target = 500;
    uint32_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic32_fetch(ep, UCT_ATOMIC_OP_ADD, 123,
                      &result, (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(500U, result) << "old value should be 500";
    EXPECT_EQ(623U, target) << "target should be 500 + 123";
    teardown_target(rk);
}

UCS_TEST_P(test_cxi_amo, cswap32_match)
{
    uint32_t target = 10;
    uint32_t result = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    ucs_status_t st = uct_ep_atomic_cswap32(ep, 10, 20,
                      (uint64_t)(uintptr_t)&target,
                      rk.bundle.rkey, &result, NULL);
    ASSERT_EQ(UCS_INPROGRESS, st);
    poll_fetch(ep);

    EXPECT_EQ(10U, result) << "old value should be 10";
    EXPECT_EQ(20U, target) << "target should be swapped to 20";
    teardown_target(rk);
}


/* -------------------------------------------------------------------------
 * Multiple sequential atomics
 * -------------------------------------------------------------------------
 */

UCS_TEST_P(test_cxi_amo, atomic64_sequential_adds)
{
    uint64_t target = 0;
    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);
    rkey_ctx rk = setup_target(&target, sizeof(target));

    static const int N = 100;
    for (int i = 0; i < N; i++) {
        ASSERT_UCS_OK(uct_ep_atomic64_post(ep, UCT_ATOMIC_OP_ADD, 1,
                      (uint64_t)(uintptr_t)&target, rk.bundle.rkey));
    }
    flush_ep(sender(), ep);

    EXPECT_EQ((uint64_t)N, target) << "100 atomic adds of 1 should give 100";
    teardown_target(rk);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_amo, cxi)
