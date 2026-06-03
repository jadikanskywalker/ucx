/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI endpoint implementation — ep_create, ep_destroy, ep_flush, ep_fence.
 *
 * RMA operations (ep_put_zcopy, ep_get_zcopy) live in cxi_rma.c.
 *
 * ep_create precomputes dfa_rma[0] for LAC 0 and marks it valid.  Additional
 * LAC DFAs (1-7, only when built with --enable-huge-pages) are built lazily
 * in cxi_rma.c on first use of that LAC in an rkey.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_ep.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <ucs/sys/string.h>

#include <cxi_prov_hw.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

static UCS_F_ALWAYS_INLINE uct_cxi_md_t *
uct_cxi_ep_md(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(uct_cxi_ep_iface(ep)->super.md, uct_cxi_md_t);
}


/* -------------------------------------------------------------------------
 * ep_create / ep_destroy
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_create — allocate and connect an EP to a remote iface.
 *
 * Reads device_addr (nid) and iface_addr (pid) from params, stores them in
 * the EP, and precomputes dfa_rma[0] for LAC 0.  Additional LAC DFAs are
 * built lazily in cxi_rma.c on first use.
 */
ucs_status_t uct_cxi_ep_create(const uct_ep_params_t *params, uct_ep_h *ep_p)
{
    uct_cxi_iface_t             *iface;
    uct_cxi_md_t                *md;
    uct_cxi_ep_t                *ep;
    const uct_cxi_device_addr_t *dev_addr;
    const uct_cxi_iface_addr_t  *iface_addr;

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);

    iface = ucs_derived_of(params->iface, uct_cxi_iface_t);
    md    = ucs_derived_of(iface->super.md, uct_cxi_md_t);

    ep = ucs_malloc(sizeof(*ep), "uct_cxi_ep");
    if (ep == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    UCS_CLASS_INIT(uct_base_ep_t, &ep->super, &iface->super);

    dev_addr   = (const uct_cxi_device_addr_t *)params->dev_addr;
    iface_addr = (const uct_cxi_iface_addr_t  *)params->iface_addr;

    ep->rem_nid     = dev_addr->nid;
    ep->rem_pid     = iface_addr->pid;
    ep->outstanding = 0;

    /* Build all UCT_CXI_MAX_LACS DFAs at creation time (pid_offset = lac index)
     * so the hot path can index ep->dfa_rma[rkey->lac] without any check. */
    {
        uint8_t lac;
        for (lac = 0; lac < UCT_CXI_MAX_LACS; lac++) {
            cxi_build_dfa(ep->rem_nid, ep->rem_pid, (uint32_t)md->pid_bits,
                          (uint32_t)lac,
                          &ep->dfa_rma[lac], &ep->dfa_rma_idx_ext[lac]);
        }
    }

    ucs_debug("cxi ep %p create nid 0x%x pid %u",
              ep, ep->rem_nid, ep->rem_pid);

    *ep_p = &ep->super.super;
    return UCS_OK;
}

void uct_cxi_ep_destroy(uct_ep_h tl_ep)
{
    uct_cxi_ep_t *ep = ucs_derived_of(tl_ep, uct_cxi_ep_t);

    ucs_debug("cxi ep %p destroy (outstanding=%u)", ep, ep->outstanding);
    ucs_free(ep);
}


/* -------------------------------------------------------------------------
 * ep_flush / ep_fence
 * -------------------------------------------------------------------------
 */

/*
 * uct_cxi_ep_flush — poll-based flush.
 *
 * Returns UCS_OK when all sends posted on this EP have been acknowledged.
 * Returns UCS_INPROGRESS while ACKs are pending.
 */
ucs_status_t uct_cxi_ep_flush(uct_ep_h tl_ep, unsigned flags,
                               uct_completion_t *comp)
{
    uct_cxi_ep_t *ep = ucs_derived_of(tl_ep, uct_cxi_ep_t);

    if (ep->outstanding == 0) {
        UCT_TL_EP_STAT_FLUSH(ucs_derived_of(tl_ep, uct_base_ep_t));
        return UCS_OK;
    }

    UCT_TL_EP_STAT_FLUSH_WAIT(ucs_derived_of(tl_ep, uct_base_ep_t));
    return UCS_INPROGRESS;
}

/*
 * uct_cxi_ep_fence — no-op with stats.
 *
 * The CXI TX command queue is hardware-ordered: commands posted to the same
 * CMDQ are executed in submission order, so no software fence is needed.
 */
ucs_status_t uct_cxi_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
    UCT_TL_EP_STAT_FENCE(ucs_derived_of(tl_ep, uct_base_ep_t));
    return UCS_OK;
}
