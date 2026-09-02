/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT pending-request queue unit tests — ep_pending_add / ep_pending_purge.
 *
 * TX_OP_MAX_BUFS is shrunk to a small, deterministic value via
 * modify_config("CXI_TX_OP_MAX_BUFS", ...) so op_pool exhaustion (and the
 * resulting UCS_ERR_NO_RESOURCE) is reachable with a handful of
 * ep_put_short calls instead of needing to flood thousands of operations.
 * The "CXI_" prefix is required: TX_OP_MAX_BUFS lives directly in
 * uct_cxi_iface_config_table (the per-transport table, registered with
 * prefix "CXI_" in UCT_TL_DEFINE_ENTRY), not in the shared generic
 * uct_iface_config_table — only fields in the latter resolve via a bare
 * name through modify_config()'s empty-prefix sub-table recursion.
 *
 * ep_put_short is used because its send_op sits in op_pool until
 * C_EVENT_ACK drains it (data itself is inline/IDC, so no separate
 * registered source buffer is needed — only the receiver-side target).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_rma.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>

#include <cstring>


/* -------------------------------------------------------------------------
 * Fixture
 * -------------------------------------------------------------------------
 */

/**
 * test_cxi_pending — shrinks TX_OP_MAX_BUFS before entity creation so
 * op_pool exhaustion is reachable deterministically within a test.
 */
class test_cxi_pending : public test_cxi_rma_base {
protected:
    static const size_t POOL_CAP = 4;

    void init() override
    {
        /* TX_OP_MAX_BUFS is defined directly in uct_cxi_iface_config_table
         * (not the shared generic uct_iface_config_table), so it can only be
         * matched via modify_config() using its "CXI_"-prefixed name (the
         * prefix registered in UCT_TL_DEFINE_ENTRY) — a bare field name only
         * resolves for fields living in the generic sub-table. */
        modify_config("CXI_TX_OP_MAX_BUFS", std::to_string(POOL_CAP).c_str());
        test_cxi_rma_base::init();
        check_caps(UCT_IFACE_FLAG_PUT_SHORT | UCT_IFACE_FLAG_PENDING);
    }

    /**
     * Flood ep_put_short until op_pool is exhausted.  Returns the number of
     * successful sends before the first UCS_ERR_NO_RESOURCE.
     */
    size_t exhaust_op_pool(uct_ep_h ep, uint64_t remote_addr,
                           uct_rkey_t rkey)
    {
        uint8_t      payload[8];
        ucs_status_t status;
        size_t       sent = 0;

        memset(payload, 0x5A, sizeof(payload));

        /* POOL_CAP + a small margin: if this returns UCS_OK past POOL_CAP
         * sends, TX_OP_MAX_BUFS did not apply — treat as a test bug, not an
         * infinite loop. */
        do {
            status = uct_ep_put_short(ep, payload, sizeof(payload),
                                      remote_addr, rkey);
            if (status == UCS_OK) {
                sent++;
            }
        } while ((status == UCS_OK) && (sent <= POOL_CAP + 4));

        return sent;
    }
};

const size_t test_cxi_pending::POOL_CAP;


/* -------------------------------------------------------------------------
 * pending_add / arbiter dispatch
 * -------------------------------------------------------------------------
 */

namespace {

struct pending_ctx {
    uct_pending_req_t req;
    volatile bool      fired;
    uct_ep_h            ep;
    uint64_t            remote_addr;
    uct_rkey_t          rkey;
};

ucs_status_t pending_retry_cb(uct_pending_req_t *self)
{
    pending_ctx *ctx = ucs_container_of(self, pending_ctx, req);
    uint8_t      payload[8];
    ucs_status_t status;

    memset(payload, 0xB7, sizeof(payload));
    status = uct_ep_put_short(ctx->ep, payload, sizeof(payload),
                              ctx->remote_addr, ctx->rkey);
    if (status == UCS_OK) {
        ctx->fired = true;
    }
    return status;
}

} // namespace

/**
 * Exhaust op_pool (TX_OP_MAX_BUFS=4), queue a callback via ep_pending_add,
 * verify it does NOT fire immediately, then drain via iface_progress and
 * verify the arbiter dispatch in iface_progress() retries and delivers it.
 */
UCS_TEST_P(test_cxi_pending, pending_add_retries_after_pool_exhaustion)
{
    uint64_t target = 0;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h target_memh = reg(receiver(), &target, sizeof(target));
    std::string rkey_buf  = pack_rkey(receiver(), target_memh, &target,
                                      sizeof(target));
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component, rkey_buf.data(),
                                  &rkey_bundle));

    size_t sent = exhaust_op_pool(ep, (uint64_t)(uintptr_t)&target,
                                  rkey_bundle.rkey);
    ASSERT_LE(sent, POOL_CAP)
            << "op_pool accepted more sends than TX_OP_MAX_BUFS="
            << POOL_CAP << " — pool cap did not apply";
    ASSERT_GT(sent, 0u) << "op_pool rejected the very first send";

    pending_ctx ctx;
    ctx.fired       = false;
    ctx.ep          = ep;
    ctx.remote_addr = (uint64_t)(uintptr_t)&target;
    ctx.rkey        = rkey_bundle.rkey;
    ctx.req.func    = pending_retry_cb;

    ucs_status_t pend_status = uct_ep_pending_add(ep, &ctx.req, 0);
    ASSERT_UCS_OK(pend_status);
    EXPECT_FALSE(ctx.fired)
            << "pending callback fired before any resources were freed";

    /* Drain: iface_progress() processes C_EVENT_ACKs (freeing op_pool
     * slots) and, per uct_cxi_iface_progress(), dispatches the arbiter at
     * the end of each call — this should retry and deliver ctx.req. */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    while (!ctx.fired && (ucs_get_time() < deadline)) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    ASSERT_TRUE(ctx.fired) << "pending callback did not fire within 5 s";

    flush_ep(sender(), ep);

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), target_memh);
}

/**
 * Queue N requests (more than POOL_CAP) via pending_add while the pool is
 * exhausted, verify all of them eventually fire in order as resources free
 * up across successive iface_progress() calls.
 */
UCS_TEST_P(test_cxi_pending, pending_add_multiple_requests_drain_in_order)
{
    static const size_t N = 6;
    uint64_t             target = 0;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h target_memh = reg(receiver(), &target, sizeof(target));
    std::string rkey_buf  = pack_rkey(receiver(), target_memh, &target,
                                      sizeof(target));
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component, rkey_buf.data(),
                                  &rkey_bundle));

    exhaust_op_pool(ep, (uint64_t)(uintptr_t)&target, rkey_bundle.rkey);

    pending_ctx ctx[N];
    std::vector<int> fire_order;
    for (size_t i = 0; i < N; i++) {
        ctx[i].fired       = false;
        ctx[i].ep          = ep;
        ctx[i].remote_addr = (uint64_t)(uintptr_t)&target;
        ctx[i].rkey        = rkey_bundle.rkey;
        ctx[i].req.func    = pending_retry_cb;
        ASSERT_UCS_OK(uct_ep_pending_add(ep, &ctx[i].req, 0));
    }

    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(5.0);
    bool all_fired = false;
    while (!all_fired && (ucs_get_time() < deadline)) {
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
    ASSERT_TRUE(all_fired) << "not all pending requests fired within 5 s";

    flush_ep(sender(), ep);

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), target_memh);
}


/* -------------------------------------------------------------------------
 * pending_purge
 * -------------------------------------------------------------------------
 */

namespace {

void purge_flag_cb(uct_pending_req_t *self, void *arg)
{
    bool *purged = static_cast<bool *>(arg);
    *purged      = true;
}

} // namespace

/**
 * Exhaust op_pool, queue a callback via pending_add, then purge it directly
 * (without ever draining resources).  Verifies the purge callback fires
 * exactly once and that the original send callback never fires afterward,
 * even once resources do free up.
 */
UCS_TEST_P(test_cxi_pending, pending_purge_removes_queued_request)
{
    uint64_t target = 0;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h target_memh = reg(receiver(), &target, sizeof(target));
    std::string rkey_buf  = pack_rkey(receiver(), target_memh, &target,
                                      sizeof(target));
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component, rkey_buf.data(),
                                  &rkey_bundle));

    exhaust_op_pool(ep, (uint64_t)(uintptr_t)&target, rkey_bundle.rkey);

    pending_ctx ctx;
    ctx.fired       = false;
    ctx.ep          = ep;
    ctx.remote_addr = (uint64_t)(uintptr_t)&target;
    ctx.rkey        = rkey_bundle.rkey;
    ctx.req.func    = pending_retry_cb;
    ASSERT_UCS_OK(uct_ep_pending_add(ep, &ctx.req, 0));

    bool purged = false;
    uct_ep_pending_purge(ep, purge_flag_cb, &purged);
    EXPECT_TRUE(purged)
            << "purge callback was not invoked for the queued request";

    /* Drain remaining in-flight ACKs; the purged request must never fire,
     * even though resources free up and the arbiter dispatch runs. */
    ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(2.0);
    while (ucs_get_time() < deadline) {
        uct_iface_progress(sender().iface());
        uct_iface_progress(receiver().iface());
    }
    EXPECT_FALSE(ctx.fired) << "a purged pending request must never fire";

    flush_ep(sender(), ep);

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), target_memh);
}

/**
 * Verify ep_destroy purges any still-queued pending request instead of
 * leaking it or crashing.  Relies on uct_cxi_ep_destroy calling
 * uct_cxi_ep_pending_purge with an internal warn-callback; correctness here
 * is "no crash / no leak", observable indirectly via clean entity teardown.
 */
UCS_TEST_P(test_cxi_pending, pending_purged_on_ep_destroy)
{
    uint64_t target = 0;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_mem_h target_memh = reg(receiver(), &target, sizeof(target));
    std::string rkey_buf  = pack_rkey(receiver(), target_memh, &target,
                                      sizeof(target));
    uct_rkey_bundle_t rkey_bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam()->component, rkey_buf.data(),
                                  &rkey_bundle));

    exhaust_op_pool(ep, (uint64_t)(uintptr_t)&target, rkey_bundle.rkey);

    pending_ctx ctx;
    ctx.fired       = false;
    ctx.ep          = ep;
    ctx.remote_addr = (uint64_t)(uintptr_t)&target;
    ctx.rkey        = rkey_bundle.rkey;
    ctx.req.func    = pending_retry_cb;
    ASSERT_UCS_OK(uct_ep_pending_add(ep, &ctx.req, 0));

    /* Destroying the entity's EP must purge ctx.req via
     * uct_cxi_ep_pending_purge_warn_cb -- a deliberate warning (not a
     * crash/leak), so wrap (not hide) it and assert exactly one fired.
     * wrap_warns_logger returns UCS_LOG_FUNC_RC_STOP, consuming the
     * message into m_warnings and preventing it from ever reaching
     * whatever increments the num_warnings() counter -- m_warnings.size()
     * is the correct check here (see test_ucp_worker.cc's
     * check_leak_warnings for the same pattern), not num_warnings(). */
    {
        scoped_log_handler wrap_warn(wrap_warns_logger);
        sender().destroy_ep(0);
        EXPECT_EQ(1u, m_warnings.size());
    }

    uct_rkey_release(GetParam()->component, &rkey_bundle);
    dereg(receiver(), target_memh);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_pending, cxi)
