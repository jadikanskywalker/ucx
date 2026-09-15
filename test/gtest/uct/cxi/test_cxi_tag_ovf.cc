/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT hardware tag-matching overflow-buffer ref-counting tests --
 * verifies uct_cxi_iface_tag_handle_ovf_arrival()'s "unified overflow-buffer
 * lifecycle" design (see the design plan's Step 2): a buffer generation must
 * not be reposted -- and its memory made eligible for reuse -- until every
 * unexpected message that landed in it has actually been resolved via its
 * own SEARCH_AND_DELETE confirmation, not just on the triggering
 * (auto-unlinked) arrival alone.
 *
 * TAG_OVERFLOW_NUM_BUFS is shrunk to 1 (so every arrival in these tests
 * lands in the same, easily-identified ring slot, buf_idx 0) and
 * TAG_OVERFLOW_BUF_SIZE/TAG_EAGER_MAX to a small fixed value (so crossing
 * the fixed UCT_CXI_TAG_OVF_MIN_FREE == 256 B auto-unlink margin is
 * reachable with a couple of small sends instead of needing kilobytes of
 * traffic against the default 512k buffer) via modify_config(), matching
 * test_cxi_pending's own precedent for shrinking a CXI-specific config value
 * ahead of entity creation.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_rma.h"
#include "test_cxi_tag.h"

#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_tag.h>
#include <uct/cxi/base/cxi_md.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <cstring>
#include <vector>
#include <unistd.h>


namespace {

struct recv_record {
    uct_tag_t             tag;
    uint64_t              imm;
    std::vector<uint8_t>  data;
};

struct multi_unexp_ctx {
    std::vector<recv_record> msgs;
};

ucs_status_t multi_unexp_eager_cb(void *arg, void *data, size_t length,
                                  unsigned flags, uct_tag_t stag,
                                  uint64_t imm, void **context)
{
    multi_unexp_ctx *ctx = static_cast<multi_unexp_ctx *>(arg);
    recv_record       rec;
    rec.tag = stag;
    rec.imm = imm;
    rec.data.assign(static_cast<uint8_t *>(data),
                    static_cast<uint8_t *>(data) + length);
    ctx->msgs.push_back(rec);
    return UCS_OK;
}

ucs_status_t multi_unexp_rndv_cb(void *arg, unsigned flags, uint64_t stag,
                                 const void *header, unsigned header_length,
                                 uint64_t remote_addr, size_t length,
                                 const void *rkey_buf)
{
    /* Unused by these tests -- present only because create_entity()
     * requires a real callback (see test_cxi_tag.h's identical stub). */
    return UCS_OK;
}

} // namespace


/**
 * test_cxi_tag_ovf -- two-entity fixture with a shrunk, single-buffer
 * overflow ring and an unexpected-message context that accumulates every
 * arrival (unlike test_cxi_tag_base's m_unexp, which only ever keeps the
 * most recent one) -- these tests deliberately keep more than one
 * unexpected message in flight at once.
 */
class test_cxi_tag_ovf : public test_cxi_rma_base {
protected:
    multi_unexp_ctx m_unexp;

    void init() override
    {
        modify_config("CXI_TAG_OVERFLOW_NUM_BUFS", "1");
        modify_config("CXI_TAG_OVERFLOW_BUF_SIZE", "1024");
        modify_config("CXI_TAG_EAGER_MAX", "1024");

        /* Deliberately not calling test_cxi_rma_base::init() -- it uses the
         * no-arg create_entity(), which substitutes a dummy eager_cb we
         * can't observe (same reasoning as test_cxi_tag_base::init()). */
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(
                0, NULL, multi_unexp_eager_cb, multi_unexp_rndv_cb,
                &m_unexp, &m_unexp)); /* sender   */
        m_entities.push_back(uct_test::create_entity(
                0, NULL, multi_unexp_eager_cb, multi_unexp_rndv_cb,
                &m_unexp, &m_unexp)); /* receiver */

        check_caps_skip(UCT_IFACE_FLAG_TAG_EAGER_SHORT |
                        UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
                        UCT_IFACE_FLAG_TAG_EAGER_ZCOPY);
    }

    /** Poll sender + receiver progress until at least @a n unexpected
     * messages have been delivered, or timeout. */
    void poll_until_count(size_t n, double timeout_sec = 5.0)
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(timeout_sec);
        while ((m_unexp.msgs.size() < n) && (ucs_get_time() < deadline)) {
            uct_iface_progress(sender().iface());
            uct_iface_progress(receiver().iface());
        }
        ASSERT_GE(m_unexp.msgs.size(), n)
                << "only " << m_unexp.msgs.size() << "/" << n
                << " unexpected messages delivered after " << timeout_sec
                << " s";
    }

    static uct_cxi_iface_t *cxi_iface(entity &e)
    {
        return ucs_derived_of(e.iface(), uct_cxi_iface_t);
    }

    /** Mirrors uct_cxi_iface_tag_ovf_buf_idx() (cxi_tag.c, static there) --
     * duplicated here so raw-event diagnostics can print which ring slot
     * an event's own event->tgt_long.start actually maps to. */
    static long ovf_buf_idx_of(uct_cxi_iface_t *iface, uint64_t start)
    {
        uint64_t base_iova = iface->tag.rx_mh.iova_offset +
                            (uint64_t)(uintptr_t)iface->tag.rx_base;
        return (long)((start - base_iova) / iface->tag.buf_size);
    }
};


/*
 * Fills the single overflow ring buffer with two unexpected messages back
 * to back, before the receiver's software ever looks at the EQ -- the
 * second one crosses UCT_CXI_TAG_OVF_MIN_FREE and triggers auto_unlinked on
 * its own arrival event. Confirms the ref-counting design: the generation
 * must not be reposted (and its memory made eligible for reuse) until BOTH
 * messages have actually been resolved via their own SEARCH_AND_DELETE
 * confirmations -- not just on the triggering (auto-unlinked) arrival
 * alone, which is what the pre-Step-2 code did unconditionally.
 */
UCS_TEST_P(test_cxi_tag_ovf, no_premature_repost)
{
    static const uct_tag_t TAG_A  = 0xA000000000000001ULL;
    static const uct_tag_t TAG_B  = 0xB000000000000002ULL;
    static const uct_tag_t TAG_C  = 0xC000000000000003ULL;
    static const size_t    LEN_A  = 300;
    static const size_t    LEN_B  = 500; /* 300+500=800; buf_size(1024)-800
                                           * =224 < MIN_FREE(256) -- triggers
                                           * auto_unlinked on B's own Put. */
    static const size_t    LEN_C  = 64;
    static const uint8_t   FILL_A = 0xAA;
    static const uint8_t   FILL_B = 0xBB;
    static const uint8_t   FILL_C = 0xCC;

    sender().connect_to_iface(0, receiver());
    uct_ep_h ep = sender().ep(0);

    uct_cxi_iface_t *riface = cxi_iface(receiver());
    ASSERT_EQ(1u, riface->tag.num_bufs)
            << "test assumes a single ring buffer -- did the "
               "CXI_TAG_OVERFLOW_NUM_BUFS override not take effect?";

    struct pack_arg { uint8_t fill; size_t len; };
    auto pack = [](void *dst, void *a) -> size_t {
        auto *p = static_cast<pack_arg *>(a);
        memset(dst, p->fill, p->len);
        return p->len;
    };

    pack_arg arg_a = {FILL_A, LEN_A};
    pack_arg arg_b = {FILL_B, LEN_B};
    ssize_t  ret_a = uct_ep_tag_eager_bcopy(ep, TAG_A, 0, +pack, &arg_a, 0);
    ASSERT_EQ(static_cast<ssize_t>(LEN_A), ret_a);
    ssize_t  ret_b = uct_ep_tag_eager_bcopy(ep, TAG_B, 0, +pack, &arg_b, 0);
    ASSERT_EQ(static_cast<ssize_t>(LEN_B), ret_b);

    /* Real elapsed time, no progress calls yet -- let both Puts actually
     * land in the receiver's single overflow buffer before the receiver's
     * software ever looks at the EQ (same technique as
     * test_cxi_tag.delayed_match_data_copy). */
    usleep(100000);

    /* Originally this called uct_iface_progress() once and asserted an
     * intermediate ovf_refcnt[0]==2/ovf_repost_pending[0]!=0 snapshot, on
     * the assumption that a just-emitted SEARCH_AND_DELETE's own
     * confirmation couldn't plausibly already be back from hardware within
     * that same call. Real hardware disproved that: a single progress()
     * call routinely processes both arrivals AND both confirmations
     * end-to-end (loopback round-trip is evidently faster than one
     * userspace EQ-drain call), so ovf_refcnt[0] already reads 0 by the
     * time control returns here -- there is no reliable window to observe
     * the "still pending" state from outside. The test's actual,
     * timing-independent correctness claim is what's checked below: after
     * a full drain, the ref-count is back at 0, the deferred repost fired,
     * and -- the part that would actually catch a premature-repost bug --
     * neither message's data was corrupted. */
    poll_until_count(2);

    EXPECT_EQ(0u, riface->tag.ovf_refcnt[0])
            << "ref-count should be fully drained once both messages "
               "resolved";
    EXPECT_EQ(0u, riface->tag.ovf_repost_pending[0])
            << "the deferred repost should have fired once the ref-count "
               "hit zero";

    ASSERT_EQ(2u, m_unexp.msgs.size());
    const recv_record *rec_a = NULL, *rec_b = NULL;
    for (auto &rec : m_unexp.msgs) { /* delivery order isn't guaranteed */
        if (rec.tag == TAG_A) rec_a = &rec;
        if (rec.tag == TAG_B) rec_b = &rec;
    }
    ASSERT_NE(static_cast<const recv_record *>(NULL), rec_a)
            << "message A never delivered";
    ASSERT_NE(static_cast<const recv_record *>(NULL), rec_b)
            << "message B never delivered";

    ASSERT_EQ(LEN_A, rec_a->data.size());
    for (size_t i = 0; i < LEN_A; i++) {
        EXPECT_EQ(FILL_A, rec_a->data[i])
                << "A byte " << i << " corrupted -- possible premature "
                   "repost/memory reuse";
    }
    ASSERT_EQ(LEN_B, rec_b->data.size());
    for (size_t i = 0; i < LEN_B; i++) {
        EXPECT_EQ(FILL_B, rec_b->data[i])
                << "B byte " << i << " corrupted -- possible premature "
                   "repost/memory reuse";
    }

    /* Confirm the ring's single LE is genuinely usable again: a fresh
     * unexpected message must still land and be delivered correctly. */
    std::vector<uint8_t> buf_c(LEN_C, FILL_C);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG_C, buf_c.data(), LEN_C));
    poll_until_count(3);
    ASSERT_EQ(3u, m_unexp.msgs.size());
    EXPECT_EQ(TAG_C, m_unexp.msgs[2].tag);
    ASSERT_EQ(LEN_C, m_unexp.msgs[2].data.size());
    for (size_t i = 0; i < LEN_C; i++) {
        EXPECT_EQ(FILL_C, m_unexp.msgs[2].data[i]) << "C byte " << i;
    }

    flush_ep(sender(), ep);
}


/*
 * Raw hardware-event-ordering diagnostic for the "delayed match resolves
 * before the raw overflow-arrival event is even processed" finding from
 * test_cxi_tag.forced_race_search_delete_vs_priority_append (real trace:
 * [OVF-MATCHED] tag=X, THEN [OVF-RELEASE-UNDERFLOW], THEN [OVF-ARRIVAL]
 * tag=X -- the delayed-match notification for a message was processed
 * before that same message's own raw overflow-landing event).
 *
 * Deliberately does NOT call uct_iface_progress() at all -- production
 * dispatch (tag_handle_ovf_arrival/tag_handle_eager_match/tag_handle_
 * search_delete_confirm) never runs here. Instead this drains the
 * receiver's raw EQ directly (cxi_eq_get_event/cxi_eq_ack_events, the same
 * primitives cxi_iface.c's own progress loop uses) so the exact event
 * types, order, and return codes hardware actually produces can be
 * inspected and printed, uncontaminated by anything our own dispatch code
 * does in response. Reproduces the ordering with the SAME technique as
 * test_cxi_tag.delayed_match_data_copy (real elapsed time, no progress
 * calls) rather than the tight, no-delay back-to-back issuing
 * forced_race_search_delete_vs_priority_append uses -- this checks whether
 * the reordering is a general EQ-delivery property (reproduces even with
 * a "clean", unambiguous delayed match) or specific to genuine tight
 * concurrent issuing.
 *
 * Second part directly answers the open question behind Option 2 of the
 * ref-count redesign: after both raw events have already been drained
 * (i.e. after software already knows, from reading them directly, that
 * the real match already claimed this message), manually emit the exact
 * same C_CMD_TGT_SEARCH_AND_DELETE tag_handle_ovf_arrival() would have
 * issued automatically, and inspect what event type and return code IT
 * produces -- confirming (or refuting) that a SEARCH_AND_DELETE issued
 * strictly after the real match has already resolved reliably reports
 * "not found", which is what makes routing the ref-count release through
 * that confirmation instead of through tag_handle_eager_match() sound.
 */
UCS_TEST_P(test_cxi_tag_ovf, raw_event_order_and_manual_search_delete)
{
    static const uct_tag_t TAG     = 0xABCD000000000001ULL;
    static const size_t    PAY_LEN = 32;
    static const uint8_t   FILL    = 0x42;

    struct captured {
        uint8_t  event_type;
        int      rc;
        uint8_t  ptl_list;
        uint16_t buffer_id;
        uint64_t match_bits;
        uint32_t mlength;
        uint32_t rlength;
        uint8_t  rendezvous;
        uint64_t start;
    };

    sender().connect_to_iface(0, receiver());
    uct_ep_h          ep     = sender().ep(0);
    uct_cxi_iface_t  *riface = cxi_iface(receiver());

    std::vector<uint8_t> tx_buf(PAY_LEN, FILL);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG, tx_buf.data(), PAY_LEN));

    /* Real elapsed time, no progress calls on either side -- guarantee the
     * message has definitely already landed as a genuine unexpected
     * arrival before anything else happens (same technique as
     * test_cxi_tag.delayed_match_data_copy). */
    usleep(100000);

    std::vector<uint8_t> rx_buf(PAY_LEN, 0);
    uct_mem_h            rx_memh = reg(receiver(), rx_buf.data(), PAY_LEN);
    uct_cxi_tag_recv_ctx rctx;
    memset(&rctx, 0, sizeof(rctx));
    uct_iov_t iov;
    iov.buffer = rx_buf.data();
    iov.length = PAY_LEN;
    iov.memh   = rx_memh;
    iov.stride = 0;
    iov.count  = 1;

    ASSERT_UCS_OK(uct_iface_tag_recv_zcopy(receiver().iface(), TAG,
                                           UCS_MASK(64), &iov, 1,
                                           &rctx.super));

    /* Let the priority-LE APPEND and hardware's own search-on-append fully
     * resolve before software looks at anything. */
    usleep(100000);

    /* Drain the raw EQ directly -- bypasses uct_iface_progress() and thus
     * every bit of our own dispatch/ref-count logic entirely. */
    std::vector<captured> events;
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(2.0);
        while ((events.size() < 2) && (ucs_get_time() < deadline)) {
            const union c_event *ev;
            while ((ev = cxi_eq_get_event(riface->evtq)) != NULL) {
                if (ev->tgt_long.ptlte_index != riface->tag.pte->ptn) {
                    continue; /* not this PTE -- ignore for this capture */
                }
                captured c;
                c.event_type  = ev->hdr.event_type;
                c.rc          = cxi_event_rc(ev);
                c.ptl_list    = ev->tgt_long.ptl_list;
                c.buffer_id   = ev->tgt_long.buffer_id;
                c.match_bits  = ev->tgt_long.match_bits;
                c.mlength     = ev->tgt_long.mlength;
                c.rlength     = ev->tgt_long.rlength;
                c.rendezvous  = ev->tgt_long.rendezvous;
                c.start       = ev->tgt_long.start;
                events.push_back(c);
            }
            cxi_eq_ack_events(riface->evtq);
        }
    }

    ASSERT_GE(events.size(), 2u)
            << "expected at least 2 raw tag-PTE events (raw overflow "
               "arrival + delayed-match notification) within 2 s";

    for (size_t i = 0; i < events.size(); i++) {
        UCS_TEST_MESSAGE << "raw event[" << i
                         << "]: type=" << (int)events[i].event_type
                         << " rc=" << events[i].rc
                         << " ptl_list=" << (int)events[i].ptl_list
                         << " buffer_id=" << events[i].buffer_id
                         << " match_bits=0x" << std::hex
                         << events[i].match_bits << std::dec
                         << " mlength=" << events[i].mlength
                         << " rlength=" << events[i].rlength
                         << " rendezvous=" << (int)events[i].rendezvous;
    }

    /* Identify which captured event is the raw arrival (C_EVENT_PUT,
     * ptl_list==OVERFLOW) vs. the delayed-match notification
     * (C_EVENT_PUT_OVERFLOW, a real slot -- not our sentinel, we haven't
     * issued anything yet). Report the observed order rather than assert
     * a specific one -- that's the whole question this test exists to
     * answer empirically. */
    int arrival_idx = -1, match_idx = -1;
    for (size_t i = 0; i < events.size(); i++) {
        if ((events[i].event_type == C_EVENT_PUT) &&
            (events[i].ptl_list == C_PTL_LIST_OVERFLOW) &&
            (arrival_idx < 0)) {
            arrival_idx = (int)i;
        }
        if ((events[i].event_type == C_EVENT_PUT_OVERFLOW) &&
            (match_idx < 0)) {
            match_idx = (int)i;
        }
    }
    ASSERT_GE(arrival_idx, 0) << "raw overflow-arrival event never seen";
    ASSERT_GE(match_idx, 0) << "delayed-match notification event never seen";
    UCS_TEST_MESSAGE << "raw overflow arrival at index " << arrival_idx
                     << ", delayed-match notification at index " << match_idx
                     << (match_idx < arrival_idx ?
                                 " -- MATCH BEFORE ARRIVAL (confirms the "
                                 "ordering-inversion finding)" :
                                 " -- arrival before match (naively-expected "
                                 "order)");

    /* Now manually issue the exact same SEARCH_AND_DELETE
     * tag_handle_ovf_arrival() would have, targeting this tag -- both raw
     * events are already known (drained above), so this directly answers:
     * does a SEARCH_AND_DELETE issued strictly after the real match has
     * already resolved reliably report "not found"?
     *
     * use_once=1 is new here -- our production command has never set it.
     * Found via libfabric's own CXI provider: cxip_claim_ux_onload()
     * (cxip_msg_hpc.c:2704), the actual analogue of our use case (a
     * targeted single-tag SEARCH_AND_DELETE, not a wildcard onload), sets
     * cmd.target.use_once=1 with the comment "Delete first match" -- and
     * its own callback, cxip_claim_onload_cb(), RXC_FATALs if it ever sees
     * anything other than C_EVENT_PUT_OVERFLOW, meaning it structurally
     * never expects a separate C_EVENT_SEARCH terminator when use_once is
     * set. By contrast, libfabric's OTHER SEARCH_AND_DELETE user,
     * cxip_ux_onload() (a wildcard mass-onload, ignore_bits=-1UL), never
     * sets use_once, and its own callback explicitly handles C_EVENT_
     * SEARCH as a normal, expected "done" signal. The four event_*_disable
     * bits on struct c_target_cmd (event_unlink_disable/event_success_
     * disable/event_comm_disable/event_link_disable) were checked first
     * and ruled out -- they're LE-append lifecycle controls (the only
     * caller in the whole CXI provider setting any of them is
     * cxip_pte_append(), via cxi_target_cmd_setopts() in
     * /usr/include/cxi_prov_hw.h), not applicable to a command that
     * doesn't append an LE at all. */
    {
        struct c_target_cmd sd = {};
        sd.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
        sd.ptl_list       = C_PTL_LIST_UNEXPECTED;
        sd.ptlte_index    = riface->tag.pte->ptn;
        sd.match_bits     = TAG;
        sd.ignore_bits    = 0;
        sd.match_id       = CXI_MATCH_ID_ANY;
        sd.length         = -1U;
        sd.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE; /* buf_idx 0 --
                              this fixture's single ring buffer */
        sd.use_once       = 1;

        int ret = cxi_cq_emit_target(riface->tgt.cmdq, &sd);
        ASSERT_EQ(0, ret) << "manual SEARCH_AND_DELETE emit failed";
        cxi_cq_ring(riface->tgt.cmdq);
    }

    /* Drains for the FULL window unconditionally, not just until the first
     * event shows up -- an earlier version of this test stopped as soon as
     * sd_events.size() >= 1, which could (and did) miss a second,
     * slightly-later event still in flight. How many events a single
     * SEARCH_AND_DELETE actually produces here is exactly the open
     * question -- assuming a fixed count up front would bias the very
     * thing being measured. */
    std::vector<captured> sd_events;
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(1.0);
        while (ucs_get_time() < deadline) {
            const union c_event *ev;
            while ((ev = cxi_eq_get_event(riface->evtq)) != NULL) {
                if (ev->tgt_long.ptlte_index != riface->tag.pte->ptn) {
                    continue;
                }
                captured c;
                c.event_type = ev->hdr.event_type;
                c.rc         = cxi_event_rc(ev);
                c.ptl_list   = ev->tgt_long.ptl_list;
                c.buffer_id  = ev->tgt_long.buffer_id;
                c.match_bits = ev->tgt_long.match_bits;
                c.mlength    = ev->tgt_long.mlength;
                c.rlength    = ev->tgt_long.rlength;
                c.rendezvous = ev->tgt_long.rendezvous;
                c.start      = ev->tgt_long.start;
                sd_events.push_back(c);
            }
            cxi_eq_ack_events(riface->evtq);
        }
    }

    ASSERT_GE(sd_events.size(), 1u)
            << "manual SEARCH_AND_DELETE produced no event within 1 s";
    UCS_TEST_MESSAGE << "manual SEARCH_AND_DELETE produced "
                     << sd_events.size() << " event(s)";
    for (size_t i = 0; i < sd_events.size(); i++) {
        UCS_TEST_MESSAGE << "manual SEARCH_AND_DELETE event[" << i
                         << "]: type=" << (int)sd_events[i].event_type
                         << " (" << (sd_events[i].event_type ==
                                    C_EVENT_PUT_OVERFLOW ?
                                            "C_EVENT_PUT_OVERFLOW" :
                            sd_events[i].event_type == C_EVENT_SEARCH ?
                                    "C_EVENT_SEARCH" : "other")
                         << ") rc=" << sd_events[i].rc
                         << " buffer_id=" << sd_events[i].buffer_id
                         << " start=0x" << std::hex << sd_events[i].start
                         << std::dec << " -> buf_idx="
                         << ovf_buf_idx_of(riface, sd_events[i].start);
    }

    /* Both a real PUT_OVERFLOW-shaped confirmation and the C_EVENT_SEARCH
     * terminator (when both appear) echo our own command's buffer_id, so
     * this just needs any event carrying it -- prefer a PUT_OVERFLOW-shaped
     * one if present (it's the one cxi_iface.c's dispatch actually reads
     * cxi_event_rc() from today), otherwise fall back to whatever showed
     * up -- confirmed on real hardware to be only the C_EVENT_SEARCH
     * terminator for a "not found" outcome (see UCT_CXI_TAG_SEARCH_
     * DELETE_BUFIDX_BASE's doc comment in cxi_tag.h), which production
     * dispatch now routes to uct_cxi_iface_tag_handle_search_delete_
     * not_found() as a real, load-bearing release point, not a no-op. */
    int sd_confirm_idx = -1;
    for (size_t i = 0; i < sd_events.size(); i++) {
        if ((sd_events[i].buffer_id == UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE) &&
            (sd_events[i].event_type == C_EVENT_PUT_OVERFLOW)) {
            sd_confirm_idx = (int)i;
            break;
        }
    }
    if (sd_confirm_idx < 0) {
        for (size_t i = 0; i < sd_events.size(); i++) {
            if (sd_events[i].buffer_id ==
                UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE) {
                sd_confirm_idx = (int)i;
                break;
            }
        }
    }
    ASSERT_GE(sd_confirm_idx, 0)
            << "manual SEARCH_AND_DELETE's own confirmation "
               "(buffer_id==sentinel) never seen";
    EXPECT_NE(C_RC_OK, sd_events[sd_confirm_idx].rc)
            << "SEARCH_AND_DELETE issued strictly after the real match had "
               "already been drained reported C_RC_OK (\"we own it\") -- "
               "this would mean hardware let BOTH the real priority-LE "
               "match and our own SEARCH_AND_DELETE genuinely claim the "
               "same entry, not just an event-ordering artifact.";
    EXPECT_EQ(1u, sd_events.size())
            << "use_once=1 was expected to collapse the \"lost\" outcome "
               "into a single event (no separate C_EVENT_SEARCH "
               "terminator) -- see this block's own doc comment";

    /* Cleanup: never went through the normal dispatch path, so the slot
     * this receive occupies is still marked live -- reclaim it directly
     * rather than issuing yet another async command (UNLINK) whose own
     * confirmation this test has no need to observe. */
    for (unsigned i = 0; i < riface->tag.max_outstanding; i++) {
        if (riface->tag.ctx[i] == &rctx.super) {
            riface->tag.ctx[i] = NULL;
            riface->tag.free_list[riface->tag.free_count++] = (uint16_t)i;
            break;
        }
    }
    dereg(receiver(), rx_memh);

    /* Second phase: the "won" outcome (genuinely unexpected message, never
     * claimed by anything, use_once=1 SEARCH_AND_DELETE actually finds and
     * deletes it) -- confirms use_once=1 doesn't just change the "lost"
     * case, it still produces the SAME single-event shape covering both
     * outcomes, matching cxip_claim_onload_cb()'s own contract (only ever
     * expects C_EVENT_PUT_OVERFLOW, checks cxi_event_rc() for found vs.
     * not, never a companion C_EVENT_SEARCH either way). */
    static const uct_tag_t TAG2    = 0xABCD000000000002ULL;
    static const uint8_t   FILL2   = 0x24;

    std::vector<uint8_t> tx_buf2(PAY_LEN, FILL2);
    ASSERT_UCS_OK(uct_ep_tag_eager_short(ep, TAG2, tx_buf2.data(), PAY_LEN));
    usleep(100000); /* land as genuinely unexpected -- no receive ever
                      * posted for TAG2, no progress calls either side */

    /* Drain and discard TAG2's own raw overflow-arrival event first --
     * otherwise it sits unread in the EQ and gets scooped into the same
     * capture as the manual SEARCH_AND_DELETE's own event(s) below,
     * making a single-event outcome look like two (caught the hard way:
     * this exact bug produced a spurious 2-event result on the first run
     * of this test -- event[0] type=0/C_EVENT_PUT/buffer_id=0 was just
     * this leftover arrival, not part of the SEARCH_AND_DELETE at all). */
    {
        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(1.0);
        bool       seen     = false;
        while (!seen && (ucs_get_time() < deadline)) {
            const union c_event *ev;
            while ((ev = cxi_eq_get_event(riface->evtq)) != NULL) {
                if ((ev->tgt_long.ptlte_index == riface->tag.pte->ptn) &&
                    (ev->hdr.event_type == C_EVENT_PUT) &&
                    (ev->tgt_long.ptl_list == C_PTL_LIST_OVERFLOW) &&
                    (ev->tgt_long.match_bits == TAG2)) {
                    seen = true;
                }
            }
            cxi_eq_ack_events(riface->evtq);
        }
        ASSERT_TRUE(seen) << "TAG2's own raw overflow-arrival event never "
                             "seen within 1 s";
    }

    std::vector<captured> sd_events2;
    {
        struct c_target_cmd sd2 = {};
        sd2.command.opcode = C_CMD_TGT_SEARCH_AND_DELETE;
        sd2.ptl_list       = C_PTL_LIST_UNEXPECTED;
        sd2.ptlte_index    = riface->tag.pte->ptn;
        sd2.match_bits     = TAG2;
        sd2.ignore_bits    = 0;
        sd2.match_id       = CXI_MATCH_ID_ANY;
        sd2.length         = -1U;
        sd2.buffer_id      = UCT_CXI_TAG_SEARCH_DELETE_BUFIDX_BASE; /* buf_idx 0 */
        sd2.use_once       = 1;

        int ret = cxi_cq_emit_target(riface->tgt.cmdq, &sd2);
        ASSERT_EQ(0, ret) << "second manual SEARCH_AND_DELETE emit failed";
        cxi_cq_ring(riface->tgt.cmdq);

        ucs_time_t deadline = ucs_get_time() + ucs_time_from_sec(1.0);
        while (ucs_get_time() < deadline) {
            const union c_event *ev;
            while ((ev = cxi_eq_get_event(riface->evtq)) != NULL) {
                if (ev->tgt_long.ptlte_index != riface->tag.pte->ptn) {
                    continue;
                }
                captured c;
                c.event_type = ev->hdr.event_type;
                c.rc         = cxi_event_rc(ev);
                c.ptl_list   = ev->tgt_long.ptl_list;
                c.buffer_id  = ev->tgt_long.buffer_id;
                c.match_bits = ev->tgt_long.match_bits;
                c.mlength    = ev->tgt_long.mlength;
                c.rlength    = ev->tgt_long.rlength;
                c.rendezvous = ev->tgt_long.rendezvous;
                c.start      = ev->tgt_long.start;
                sd_events2.push_back(c);
            }
            cxi_eq_ack_events(riface->evtq);
        }
    }

    ASSERT_GE(sd_events2.size(), 1u)
            << "second manual SEARCH_AND_DELETE (won case) produced no "
               "event within 1 s";
    UCS_TEST_MESSAGE << "second manual SEARCH_AND_DELETE (won case) "
                     << "produced " << sd_events2.size() << " event(s)";
    for (size_t i = 0; i < sd_events2.size(); i++) {
        UCS_TEST_MESSAGE << "won-case event[" << i
                         << "]: type=" << (int)sd_events2[i].event_type
                         << " (" << (sd_events2[i].event_type ==
                                    C_EVENT_PUT_OVERFLOW ?
                                            "C_EVENT_PUT_OVERFLOW" :
                            sd_events2[i].event_type == C_EVENT_SEARCH ?
                                    "C_EVENT_SEARCH" : "other")
                         << ") rc=" << sd_events2[i].rc
                         << " buffer_id=" << sd_events2[i].buffer_id
                         << " match_bits=0x" << std::hex
                         << sd_events2[i].match_bits << std::dec
                         << " mlength=" << sd_events2[i].mlength
                         << " start=0x" << std::hex << sd_events2[i].start
                         << std::dec << " -> buf_idx="
                         << ovf_buf_idx_of(riface, sd_events2[i].start);
    }
    EXPECT_EQ(1u, sd_events2.size())
            << "use_once=1 was expected to collapse the \"won\" outcome "
               "into a single event too, matching libfabric's own "
               "cxip_claim_onload_cb() contract";
    ASSERT_FALSE(sd_events2.empty());
    EXPECT_EQ(static_cast<uint8_t>(C_EVENT_PUT_OVERFLOW),
             sd_events2[0].event_type);
    EXPECT_EQ(C_RC_OK, sd_events2[0].rc)
            << "genuinely-unexpected TAG2 should have been found+deleted";
    EXPECT_EQ(TAG2, sd_events2[0].match_bits);
    EXPECT_EQ(PAY_LEN, sd_events2[0].mlength);

    flush_ep(sender(), ep);
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_tag_ovf, cxi)
