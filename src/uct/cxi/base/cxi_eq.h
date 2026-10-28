/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI event queues (cxi_eq.c). Included only by cxi_iface.h, after
 * uct_cxi_iface_config_t.
 */

#ifndef UCT_CXI_EQ_H
#define UCT_CXI_EQ_H

#include <ucs/sys/compiler_def.h>

#include <libcxi/libcxi.h>


/* Default EQ depth (UCX_CXI_EQ_SIZE=-1) and the hardware event size. */
#define UCT_CXI_EQ_NUM_EVENTS 1024U
#define UCT_CXI_EQ_ENTRY_SIZE 64U /* sizeof(union c_event) */
/* RX EQ slots beyond the credit windows: processed events hold their slots
 * until acknowledged to the NIC in a batch. */
#define UCT_CXI_EQ_SLACK 128U

/** An event queue: the hardware EQ and its buffer, with sizing, PTE recovery
 *  and growth state. */
typedef struct uct_cxi_eq {
    /* "rx" / "tx" / "ctrl", for log messages */
    const char    *name;
    struct cxi_eq *evtq;
    /* mmap backing buffer of evtq, and its cxil_map registration */
    void          *buf;
    struct cxi_md *md;
    unsigned      num_events;
    /* Max events drained per progress call */
    unsigned      max_poll;

    /* >0 while draining before PTEs are re-enabled; one per event processed */
    unsigned      need_to_drain;
    unsigned      drain_pct;
    /* Configured reserved slots, to restore after a resize */
    unsigned      reserved_slots_cfg;
    /* Current reserved slots, as cxil_evtq_adjust_reserved_fc() reports */
    unsigned      reserved_slots;

    /* Preemptive growth: a hardware fill-threshold update triggers a resize
     * before any disable; reactive recovery stays the backstop. */
    struct {
        int           enabled;
        unsigned      thresh_pct;
        unsigned      max_len_events;
        /* From cxil_evtq_resize() to cxil_evtq_resize_complete() */
        int           resizing;
        /* New buffer awaiting C_EVENT_EQ_SWITCH, its registration, length */
        void          *pending_buf;
        struct cxi_md *pending_md;
        size_t        pending_len;
    } grow;
} uct_cxi_eq_t;

BEGIN_C_DECLS

void uct_cxi_eq_configure(uct_cxi_eq_t *eq, const char *name,
                          unsigned num_events, unsigned reserved_slots,
                          int grow_enabled,
                          const uct_cxi_iface_config_t *config);
ucs_status_t uct_cxi_eq_init(uct_cxi_eq_t *eq, struct cxil_lni *lni,
                             struct cxil_wait_obj *wait_obj);
void uct_cxi_eq_cleanup(uct_cxi_eq_t *eq);
void uct_cxi_eq_abort_resize(uct_cxi_eq_t *eq);
void uct_cxi_iface_eq_grow_start(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq);
void uct_cxi_iface_eq_grow_complete(uct_cxi_iface_t *iface, uct_cxi_eq_t *eq);

END_C_DECLS

#endif /* UCT_CXI_EQ_H */
