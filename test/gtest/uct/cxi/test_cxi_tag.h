/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * Shared fixture for CXI hardware tag-matching tests.
 */

#ifndef UCT_TEST_CXI_TAG_H
#define UCT_TEST_CXI_TAG_H

#include "test_cxi_rma.h"

#include <ucs/time/time.h>

#include <vector>
#include <cstring>


/**
 * Unexpected-message receive context -- filled by the test eager_cb when a
 * tagged message arrives with no matching priority LE posted.
 */
struct uct_cxi_tag_unexp_ctx {
    volatile bool        fired;
    uct_tag_t             tag;
    uint64_t              imm;
    std::vector<uint8_t>  data;
};

static ucs_status_t
uct_cxi_tag_eager_cb(void *arg, void *data, size_t length, unsigned flags,
                     uct_tag_t stag, uint64_t imm, void **context)
{
    uct_cxi_tag_unexp_ctx *ctx = static_cast<uct_cxi_tag_unexp_ctx *>(arg);
    ctx->tag = stag;
    ctx->imm = imm;
    ctx->data.assign(static_cast<uint8_t *>(data),
                     static_cast<uint8_t *>(data) + length);
    ctx->fired = true;
    return UCS_OK;
}

static ucs_status_t
uct_cxi_tag_rndv_cb(void *arg, unsigned flags, uint64_t stag,
                    const void *header, unsigned header_length,
                    uint64_t remote_addr, size_t length,
                    const void *rkey_buf)
{
    /* Fires for a genuinely-unexpected rendezvous arrival (no priority LE
     * posted) -- e.g. test_cxi_tag_rndv.cc's cancel_unmatched, which
     * deliberately never posts a receive. Most other tests here always
     * post a receive first, so this stub is never meaningfully exercised
     * by them -- present only because create_entity() requires a real
     * callback (see rc_mlx5's identical HW_TM gating pattern). */
    return UCS_OK;
}


/**
 * Priority-recv completion context. uct_tag_context_t must be first so a
 * uct_tag_context_t* handed back to the callbacks can be reinterpreted as
 * this larger struct.
 */
struct uct_cxi_tag_recv_ctx {
    uct_tag_context_t   super;
    volatile bool        consumed;
    volatile bool        completed;
    uct_tag_t             stag;
    uint64_t              imm;
    size_t                length;
    ucs_status_t          status;
};

static void uct_cxi_tag_consumed_cb(uct_tag_context_t *self)
{
    uct_cxi_tag_recv_ctx *ctx = reinterpret_cast<uct_cxi_tag_recv_ctx *>(self);
    EXPECT_FALSE(ctx->completed) << "tag_consumed_cb fired after completed_cb";
    ctx->consumed = true;
}

static void uct_cxi_tag_completed_cb(uct_tag_context_t *self, uct_tag_t stag,
                                     uint64_t imm, size_t length,
                                     void *inline_data, ucs_status_t status)
{
    uct_cxi_tag_recv_ctx *ctx = reinterpret_cast<uct_cxi_tag_recv_ctx *>(self);
    /* tag_consumed_cb only fires for a genuine match (it exists to tell
     * the caller "don't also match this in software") -- a real cancel
     * (UCS_ERR_CANCELED, no message ever arrived) legitimately never
     * consumes anything, so only require the ordering when this
     * completion actually represents matched data. */
    if (status != UCS_ERR_CANCELED) {
        EXPECT_TRUE(ctx->consumed) << "completed_cb fired before tag_consumed_cb";
    }
    EXPECT_EQ(static_cast<void *>(NULL), inline_data)
            << "a matched priority LE should never carry inline_data -- "
               "data lands directly in the caller's own buffer";
    ctx->stag      = stag;
    ctx->imm       = imm;
    ctx->length    = length;
    ctx->status    = status;
    ctx->completed = true;
}


/**
 * Send-side rendezvous completion context -- filled by the completion
 * callback uct_ep_tag_rndv_zcopy's own `comp` argument fires once the
 * peer's Get has reliably pulled the data (see uct_ep_tag_rndv_zcopy's own
 * doc comment in uct.h).
 */
struct uct_cxi_rndv_send_ctx {
    uct_completion_t super;
    volatile bool     fired;
};

static inline void uct_cxi_rndv_send_comp_cb(uct_completion_t *self)
{
    uct_cxi_rndv_send_ctx *ctx =
            reinterpret_cast<uct_cxi_rndv_send_ctx *>(self);
    ctx->fired = true;
}

static inline void init_rndv_send_ctx(uct_cxi_rndv_send_ctx &ctx)
{
    memset(&ctx, 0, sizeof(ctx));
    ctx.super.func   = uct_cxi_rndv_send_comp_cb;
    ctx.super.count  = 1;
    ctx.super.status = UCS_OK;
}


/**
 * test_cxi_tag_base -- two-entity fixture for CXI hardware tag-matching
 * loopback tests. Both entities are opened with real eager_cb/rndv_cb
 * (matching how UCP itself always supplies both -- HW offload is gated
 * purely on UCX_CXI_TAG_ENABLE / hardware support from there, same as
 * rc_mlx5's ucs_test_all_flags(HW_TM_EAGER_CB|HW_TM_RNDV_CB) pattern), so
 * every entity created by uct_test::create_entity() elsewhere in this test
 * suite also opens a tag PTE as a side effect -- expected, not a bug.
 */
class test_cxi_tag_base : public test_cxi_rma_base {
protected:
    uct_cxi_tag_unexp_ctx m_unexp;

    void init() override
    {
        m_unexp.fired = false;
        m_unexp.tag   = 0;
        m_unexp.imm   = 0;

        /* Deliberately not calling test_cxi_rma_base::init() -- it uses
         * the no-arg create_entity(), which substitutes a dummy eager_cb
         * we can't observe. */
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(
                0, NULL, uct_cxi_tag_eager_cb, uct_cxi_tag_rndv_cb,
                &m_unexp, &m_unexp)); /* sender   */
        m_entities.push_back(uct_test::create_entity(
                0, NULL, uct_cxi_tag_eager_cb, uct_cxi_tag_rndv_cb,
                &m_unexp, &m_unexp)); /* receiver */

        check_caps_skip(UCT_IFACE_FLAG_TAG_EAGER_SHORT |
                        UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
                        UCT_IFACE_FLAG_TAG_EAGER_ZCOPY);
    }

    static void init_recv_ctx(uct_cxi_tag_recv_ctx &ctx)
    {
        memset(&ctx, 0, sizeof(ctx));
        ctx.super.tag_consumed_cb = uct_cxi_tag_consumed_cb;
        ctx.super.completed_cb    = uct_cxi_tag_completed_cb;
        ctx.super.rndv_cb         = NULL;
    }

    /** Poll sender + receiver progress until @a flag is set or timeout. */
    void poll_until(volatile bool &flag, double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);
        while (!flag && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_TRUE(flag) << "condition not met after " << timeout_sec << " s";
    }
};

#endif /* UCT_TEST_CXI_TAG_H */
