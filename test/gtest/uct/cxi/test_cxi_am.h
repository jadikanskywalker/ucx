/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * Shared fixture for CXI Active Message tests.
 */

#ifndef UCT_TEST_CXI_AM_H
#define UCT_TEST_CXI_AM_H

#include "test_cxi_rma.h"

#include <ucs/time/time.h>

#include <vector>
#include <cstring>


/**
 * AM receive context — filled by the registered AM handler callback.
 *
 * fired:  set to true by the handler on first invocation.
 * data:   copy of the complete received buffer (header + payload for short,
 *         raw packed bytes for bcopy).
 */
struct uct_cxi_am_recv_ctx {
    volatile bool        fired;
    std::vector<uint8_t> data;
};

/**
 * AM handler callback: copies received data into ctx and sets fired.
 * Returns UCS_OK (synchronous; data in rx_buf is reusable after return).
 */
static ucs_status_t
uct_cxi_am_handler(void *arg, void *data, size_t length, unsigned flags)
{
    uct_cxi_am_recv_ctx *ctx = static_cast<uct_cxi_am_recv_ctx *>(arg);
    ctx->data.assign(static_cast<uint8_t *>(data),
                     static_cast<uint8_t *>(data) + length);
    ctx->fired = true;
    return UCS_OK;
}


/**
 * test_cxi_am_base — two-entity fixture for CXI AM loopback tests.
 *
 * Inherits two-entity setup, memory helpers, and flush_ep from
 * test_cxi_rma_base.  Adds poll_am() which drives both sender and receiver
 * progress until the AM handler fires or a 5-second deadline elapses.
 */
class test_cxi_am_base : public test_cxi_rma_base {
protected:
    void init() override
    {
        test_cxi_rma_base::init();
        /* Skip gracefully on transports that don't support AM short + bcopy. */
        check_caps(UCT_IFACE_FLAG_AM_SHORT | UCT_IFACE_FLAG_AM_BCOPY |
                   UCT_IFACE_FLAG_CB_SYNC);
    }

    /**
     * Register @a handler on @a id for the receiver's iface.
     * Fails the test if the call returns an error.
     */
    void set_am_handler(uint8_t id, uct_cxi_am_recv_ctx *ctx)
    {
        ASSERT_UCS_OK(uct_iface_set_am_handler(receiver().iface(), id,
                                               uct_cxi_am_handler, ctx, 0));
    }

    /**
     * Poll sender + receiver progress until ctx.fired is set or 5 s elapses.
     * Also drains the sender EP's outstanding ops so ep_flush eventually
     * returns UCS_OK (needed for back-to-back sends in multi tests).
     */
    void poll_am(uct_ep_h ep, uct_cxi_am_recv_ctx &ctx,
                 double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(timeout_sec);

        while (!ctx.fired && ucs_get_time() < deadline) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }

        ASSERT_TRUE(ctx.fired)
                << "AM handler not invoked after " << timeout_sec << " s";

        /* Drain sender ACKs so the EP's outstanding counter reaches zero. */
        ucs_status_t status;
        do {
            uct_iface_progress(sender().iface());
            status = uct_ep_flush(ep, 0, NULL);
        } while (status == UCS_INPROGRESS &&
                 ucs_get_time() < deadline);
    }
};

#endif /* UCT_TEST_CXI_AM_H */
