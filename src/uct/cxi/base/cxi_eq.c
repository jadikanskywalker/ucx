/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI event queues: setup, teardown and growth.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_iface.h"
#include "cxi_md.h"

#include <ucs/debug/log.h>
#include <ucs/sys/math.h>
#include <ucs/sys/string.h>

#include <string.h>
#include <sys/mman.h>


/*
 * uct_cxi_eq_configure -- reset \a eq and fill in the resolved config that
 * uct_cxi_eq_init() and the poll loop consume. \a num_events is rounded up to
 * whole pages: the driver requires a page-aligned queue length.
 */
void
uct_cxi_eq_configure(uct_cxi_eq_t *eq, const char *name, unsigned num_events,
                     unsigned reserved_slots, int grow_enabled,
                     const uct_cxi_iface_config_t *config)
{
    memset(eq, 0, sizeof(*eq));
    eq->name               = name;
    eq->num_events         = ucs_align_up(num_events, ucs_get_page_size() /
                                                      UCT_CXI_EQ_ENTRY_SIZE);
    eq->max_poll           = ucs_max(config->eq_max_poll, 1u);
    eq->drain_pct          = config->eq_drain_pct;
    eq->reserved_slots_cfg = ucs_min(reserved_slots, eq->num_events / 2);

    /* Preemptive EQ growth config — see cxi_iface.h / eq_grow_start(). The
     * ceiling is never below the size asked for. */
    eq->grow.enabled        = grow_enabled;
    eq->grow.thresh_pct     = config->eq_grow_thresh_pct;
    eq->grow.max_len_events = ucs_max(config->eq_max_len, eq->num_events);
}

/*
 * uct_cxi_eq_init -- allocate one event queue: mmap its ring buffer, pin it
 * for the NIC and create the hardware queue on top of it. The caller must
 * have filled in eq->num_events, eq->reserved_slots_cfg and eq->grow.* (the
 * resolved config) beforehand.
 */
ucs_status_t
uct_cxi_eq_init(uct_cxi_eq_t *eq, struct cxil_lni *lni,
                struct cxil_wait_obj *wait_obj)
{
    size_t             buf_len = (size_t)eq->num_events *
                                 UCT_CXI_EQ_ENTRY_SIZE;
    struct cxi_eq_attr eq_attr;
    int                ret;

    /* mmap a private anonymous buffer for the event queue ring. */
    eq->buf = mmap(NULL, buf_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (eq->buf == MAP_FAILED) {
        ucs_error("cxi mmap eq_buf size %zu failed: %m", buf_len);
        return UCS_ERR_NO_MEMORY;
    }

    /* Pin the EQ buffer so the NIC can DMA into it. */
    ret = cxil_map(lni, eq->buf, buf_len,
                   CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE, NULL, &eq->md);
    if (ret != 0) {
        ucs_error("cxi cxil_map eq_buf failed: %s", strerror(-ret));
        goto err_munmap;
    }

    /* Allocate the event queue backed by the pinned buffer.
     * reserved_slots is one-sided (blocks LPE/RX from the reservation,
     * does not cap TX) — see EQ_RESERVED_SLOTS_PCT doc and the design
     * notes in iface_progress(). */
    memset(&eq_attr, 0, sizeof(eq_attr));
    eq_attr.queue           = eq->buf;
    eq_attr.queue_len       = buf_len;
    eq_attr.reserved_slots  = eq->reserved_slots_cfg;
    eq->reserved_slots      = eq_attr.reserved_slots;
    /* status_thresh_*: a single hardware-native fill-percentage threshold
     * (see EQ_DYNAMIC_GROWTH doc) — status_thresh_count=0 when disabled
     * costs nothing (no status write-backs ever generated). */
    if (eq->grow.enabled) {
        eq_attr.status_thresh_base  = eq->grow.thresh_pct;
        eq_attr.status_thresh_delta = 0;
        eq_attr.status_thresh_count = 1;
    }
    ret = cxil_alloc_evtq(lni, eq->md, &eq_attr, wait_obj, NULL, &eq->evtq);
    if (ret != 0) {
        ucs_error("cxi cxil_alloc_evtq failed: %s", strerror(-ret));
        goto err_unmap;
    }

    return UCS_OK;

err_unmap:
    cxil_unmap(eq->md);
err_munmap:
    munmap(eq->buf, buf_len);
    return UCS_ERR_IO_ERROR;
}

/*
 * uct_cxi_eq_abort_resize -- release the pending buffer of a resize left in
 * flight (iface torn down before C_EVENT_EQ_SWITCH arrived). It leaks unless
 * freed explicitly: it's not reachable via uct_cxi_eq_cleanup(), which only
 * knows about the currently-active buffer.
 */
void uct_cxi_eq_abort_resize(uct_cxi_eq_t *eq)
{
    int ret;

    if (!eq->grow.resizing) {
        return;
    }

    ret = cxil_unmap(eq->grow.pending_md);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap pending eq.grow buffer failed: %s",
                 strerror(-ret));
    }
    munmap(eq->grow.pending_buf, eq->grow.pending_len);
}

/*
 * uct_cxi_eq_cleanup -- destroy the hardware queue and release its buffer.
 * Everything bound to the queue (PTEs, command queues) must already be gone.
 */
void uct_cxi_eq_cleanup(uct_cxi_eq_t *eq)
{
    int ret;

    ret = cxil_destroy_evtq(eq->evtq);
    if (ret != 0) {
        ucs_warn("cxi cxil_destroy_evtq failed: %s", strerror(-ret));
    }

    ret = cxil_unmap(eq->md);
    if (ret != 0) {
        ucs_warn("cxi cxil_unmap eq_md failed: %s", strerror(-ret));
    }

    munmap(eq->buf, (size_t)eq->num_events * UCT_CXI_EQ_ENTRY_SIZE);
}

/*
 * uct_cxi_iface_eq_grow_start — begin a preemptive EQ resize.
 *
 * Called from iface_progress() once a hardware fill-threshold status
 * update reports the EQ at or above eq.grow.thresh_pct. Submits a new,
 * double-sized buffer via cxil_evtq_resize() — hardware keeps writing to
 * the old buffer for a few more events, then emits C_EVENT_EQ_SWITCH
 * (handled in the main event loop) once it has switched to the new one.
 *
 * Only one resize may be in flight at a time (enforced by the driver,
 * mirrored here via eq.grow.resizing) — the caller must not call this
 * again until eq_grow_complete() has run.
 */
UCS_F_NOINLINE void
uct_cxi_iface_eq_grow_start(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq)
{
    uct_cxi_md_t  *md = uct_cxi_iface_md(iface);
    size_t         new_len;
    void          *new_buf;
    struct cxi_md *new_md;
    int            ret;

    if (eq->num_events >= eq->grow.max_len_events) {
        ucs_debug("cxi EQ at configured max_len (%u events) — "
                  "not growing further, reactive recovery remains "
                  "the backstop", eq->grow.max_len_events);
        return;
    }

    new_len = ucs_min((size_t)eq->num_events * 2,
                      (size_t)eq->grow.max_len_events) *
             UCT_CXI_EQ_ENTRY_SIZE;
    new_len = ucs_align_up_pow2(new_len, ucs_get_page_size());

    new_buf = mmap(NULL, new_len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_buf == MAP_FAILED) {
        ucs_warn("cxi EQ grow: mmap size %zu failed: %m — will retry on "
                 "next threshold crossing", new_len);
        return;
    }

    /* Same flags as the original eq_md (Step 4 in iface_open) — must land
     * on the same LAC as the EQ's current MD, or cxil_evtq_resize() below
     * rejects it. */
    ret = cxil_map(md->cxi_lni, new_buf, new_len,
                   CXI_MAP_PIN | CXI_MAP_READ | CXI_MAP_WRITE, NULL,
                   &new_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_map failed: %s — will retry on next "
                 "threshold crossing", strerror(-ret));
        munmap(new_buf, new_len);
        return;
    }

    ret = cxil_evtq_resize(eq->evtq, new_buf, new_len, new_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_evtq_resize failed: %s", strerror(-ret));
        cxil_unmap(new_md);
        munmap(new_buf, new_len);
        return;
    }

    eq->grow.pending_buf = new_buf;
    eq->grow.pending_md  = new_md;
    eq->grow.pending_len = new_len;
    eq->grow.resizing    = 1;
    ucs_debug("cxi EQ grow: resize submitted %u -> %zu events",
             eq->num_events, new_len / UCT_CXI_EQ_ENTRY_SIZE);
}

/*
 * uct_cxi_iface_eq_grow_complete — finish a preemptive EQ resize.
 *
 * Called from the main event loop on C_EVENT_EQ_SWITCH. Completes the
 * driver-side handshake, frees the old buffer, and re-applies the
 * reserved-slots percentage against the new (larger) size — otherwise
 * the reserved floor silently shrinks as a fraction of the queue on
 * every doubling.
 */
UCS_F_NOINLINE void
uct_cxi_iface_eq_grow_complete(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq)
{
    void          *old_buf = eq->buf;
    struct cxi_md *old_md  = eq->md;
    size_t         old_len = (size_t)eq->num_events *
                             UCT_CXI_EQ_ENTRY_SIZE;
    unsigned       target_reserved;
    int            ret;

    if (!eq->grow.resizing) {
        ucs_warn("cxi C_EVENT_EQ_SWITCH with no resize in flight — ignoring");
        return;
    }

    ret = cxil_evtq_resize_complete(eq->evtq);
    if (ret != 0) {
        ucs_error("cxi EQ grow: cxil_evtq_resize_complete failed: %s — "
                  "EQ remains at %u events", strerror(-ret),
                  eq->num_events);
        return;
    }

    ret = cxil_unmap(old_md);
    if (ret != 0) {
        ucs_warn("cxi EQ grow: cxil_unmap old buffer failed: %s",
                 strerror(-ret));
    }
    munmap(old_buf, old_len);

    eq->buf        = eq->grow.pending_buf;
    eq->md          = eq->grow.pending_md;
    eq->num_events = (unsigned)(eq->grow.pending_len /
                                      UCT_CXI_EQ_ENTRY_SIZE);
    eq->grow.pending_buf = NULL;
    eq->grow.pending_md  = NULL;
    eq->grow.pending_len = 0;
    eq->grow.resizing    = 0;

    target_reserved = eq->reserved_slots_cfg;
    ret = cxil_evtq_adjust_reserved_fc(
            eq->evtq, (int)target_reserved - (int)eq->reserved_slots);
    if (ret < 0) {
        ucs_warn("cxi EQ grow: reserved-slots adjust failed: %s",
                 strerror(-ret));
    } else {
        eq->reserved_slots = (unsigned)ret;
    }

    ucs_debug("cxi EQ grown: now %u events", eq->num_events);
}
