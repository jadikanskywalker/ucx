/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT Atomic Memory Operations.
 *
 * All AMOs use restricted-mode IDC commands: c_cstate_cmd (carries user_ptr,
 * eq, write_lac) followed by c_idc_amo_cmd (carries dfa, remote_offset,
 * operands).  Single cxi_cq_ring after both commands.
 *
 * Post (non-fetching): send_op from op_pool, C_EVENT_ACK.  Returns UCS_OK.
 * Fetch:               send_desc from desc_pool (registered result buffer),
 *                      C_EVENT_REPLY writes result to desc data area.
 *                      Completion handler copies to *result.  Returns UCS_INPROGRESS.
 * CSWAP:               same as fetch, op1=swap, op2=compare, CSWAP_EQ.
 *
 * Target side: existing RMA catch-all LEs (restricted, op_put=1, op_get=1)
 * handle atomics.  No additional target setup needed.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cxi_amo.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>


static UCS_F_ALWAYS_INLINE uct_cxi_iface_t *
uct_cxi_amo_ep_iface(uct_cxi_ep_t *ep)
{
    return ucs_derived_of(ep->super.super.iface, uct_cxi_iface_t);
}

static const uint8_t uct_cxi_amo_op_table[] = {
    [UCT_ATOMIC_OP_ADD]  = C_AMO_OP_SUM,
    [UCT_ATOMIC_OP_AND]  = C_AMO_OP_BAND,
    [UCT_ATOMIC_OP_OR]   = C_AMO_OP_BOR,
    [UCT_ATOMIC_OP_XOR]  = C_AMO_OP_BXOR,
    [UCT_ATOMIC_OP_SWAP] = C_AMO_OP_CSWAP,
};

/*
 * On failure (status != UCS_OK), desc's buffer was never actually written
 * by the remote — skip the copy rather than deliver a stale/uninitialized
 * "result" to the caller as if the fetch/cswap had actually happened.
 */
static void uct_cxi_amo_fetch_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_send_desc_t *desc = (uct_cxi_send_desc_t *)op;

    if (status == UCS_OK) {
        memcpy(desc->unpack_arg, desc + 1, desc->length);
    }
    if (op->comp != NULL) {
        uct_invoke_completion(op->comp, status);
    }
    ucs_mpool_put(desc);
}


/* -------------------------------------------------------------------------
 * Post (non-fetching) atomics
 * -------------------------------------------------------------------------
 */

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_ep_atomic_post_common(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                              uint64_t value, uint64_t remote_addr,
                              uct_rkey_t rkey, uint8_t amo_type)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_amo_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_op_t    *op;
    int                   ret;

    if (uct_cxi_ep_fc_blocked(ep, iface)) {
        return UCS_ERR_NO_RESOURCE;
    }

    op = ucs_mpool_get(&iface->tx.op_pool);
    if (ucs_unlikely(op == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }
    op->ep      = ep;
    op->comp    = NULL;
    op->handler = NULL;

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 1;
        cstate.index_ext           = ep->dfa_rma_idx_ext[rkey_p->lac];
        cstate.eq                  = iface->evtq->eqn;
        cstate.user_ptr            = (uint64_t)(uintptr_t)op;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_amo_cmd amo = {};
        amo.idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
        amo.idc_header.remote_offset = rkey_p->iova + remote_addr;
        amo.atomic_op                = uct_cxi_amo_op_table[opcode];
        amo.atomic_type              = amo_type;
        amo.op1_word1                = value;

        ret = cxi_cq_emit_idc_amo(iface->tx.cmdq, &amo, false);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(op);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    return UCS_OK;
}

ucs_status_t uct_cxi_ep_atomic64_post(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint64_t value, uint64_t remote_addr,
                                       uct_rkey_t rkey)
{
    return uct_cxi_ep_atomic_post_common(tl_ep, opcode, value, remote_addr,
                                         rkey, C_AMO_TYPE_UINT64_T);
}

ucs_status_t uct_cxi_ep_atomic32_post(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint32_t value, uint64_t remote_addr,
                                       uct_rkey_t rkey)
{
    return uct_cxi_ep_atomic_post_common(tl_ep, opcode, (uint64_t)value,
                                         remote_addr, rkey,
                                         C_AMO_TYPE_UINT32_T);
}


/* -------------------------------------------------------------------------
 * Fetch atomics
 * -------------------------------------------------------------------------
 */

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_ep_atomic_fetch_common(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                               uint64_t value, void *result,
                               uint64_t remote_addr, uct_rkey_t rkey,
                               uct_completion_t *comp, uint8_t amo_type,
                               size_t result_size)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_amo_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_desc_t  *desc;
    int                   ret;

    if (uct_cxi_ep_fc_blocked(ep, iface)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->op.ep      = ep;
    desc->op.comp    = comp;
    desc->op.handler = uct_cxi_amo_fetch_comp;
    desc->unpack_arg = result;
    desc->length     = result_size;

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 1;
        cstate.write_lac           = desc->lac;
        cstate.index_ext           = ep->dfa_rma_idx_ext[rkey_p->lac];
        cstate.eq                  = iface->evtq->eqn;
        cstate.user_ptr            = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_amo_cmd amo = {};
        amo.idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
        amo.idc_header.remote_offset = rkey_p->iova + remote_addr;
        amo.atomic_op                = uct_cxi_amo_op_table[opcode];
        amo.atomic_type              = amo_type;
        amo.local_addr               = desc->iova;
        amo.op1_word1                = value;

        if (opcode == UCT_ATOMIC_OP_SWAP) {
            amo.cswap_op  = C_AMO_OP_CSWAP_NE;
            amo.op2_word1 = value;
        }

        ret = cxi_cq_emit_idc_amo(iface->tx.cmdq, &amo, true);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    return UCS_INPROGRESS;
}

ucs_status_t uct_cxi_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                        uint64_t value, uint64_t *result,
                                        uint64_t remote_addr, uct_rkey_t rkey,
                                        uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                          remote_addr, rkey, comp,
                                          C_AMO_TYPE_UINT64_T, sizeof(uint64_t));
}

ucs_status_t uct_cxi_ep_atomic32_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                        uint32_t value, uint32_t *result,
                                        uint64_t remote_addr, uct_rkey_t rkey,
                                        uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_fetch_common(tl_ep, opcode, (uint64_t)value,
                                          result, remote_addr, rkey, comp,
                                          C_AMO_TYPE_UINT32_T, sizeof(uint32_t));
}


/* -------------------------------------------------------------------------
 * Compare-and-swap
 * -------------------------------------------------------------------------
 */

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_ep_atomic_cswap_common(uct_ep_h tl_ep, uint64_t compare,
                               uint64_t swap, uint64_t remote_addr,
                               uct_rkey_t rkey, void *result,
                               uct_completion_t *comp, uint8_t amo_type,
                               size_t result_size)
{
    uct_cxi_ep_t         *ep     = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t      *iface  = uct_cxi_amo_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t *)(uintptr_t)rkey;
    uct_cxi_send_desc_t  *desc;
    int                   ret;

    if (uct_cxi_ep_fc_blocked(ep, iface)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = ucs_mpool_get(&iface->tx.desc_pool);
    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return UCS_ERR_NO_RESOURCE;
    }
    desc->op.ep      = ep;
    desc->op.comp    = comp;
    desc->op.handler = uct_cxi_amo_fetch_comp;
    desc->unpack_arg = result;
    desc->length     = result_size;

    {
        struct c_cstate_cmd cstate = {};
        cstate.event_send_disable  = 1;
        cstate.restricted          = 1;
        cstate.write_lac           = desc->lac;
        cstate.index_ext           = ep->dfa_rma_idx_ext[rkey_p->lac];
        cstate.eq                  = iface->evtq->eqn;
        cstate.user_ptr            = (uint64_t)(uintptr_t)desc;

        ret = cxi_cq_emit_c_state(iface->tx.cmdq, &cstate);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }

    {
        struct c_idc_amo_cmd amo = {};
        amo.idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
        amo.idc_header.remote_offset = rkey_p->iova + remote_addr;
        amo.atomic_op                = C_AMO_OP_CSWAP;
        amo.atomic_type              = amo_type;
        amo.cswap_op                 = C_AMO_OP_CSWAP_EQ;
        amo.local_addr               = desc->iova;
        amo.op1_word1                = swap;
        amo.op2_word1                = compare;

        ret = cxi_cq_emit_idc_amo(iface->tx.cmdq, &amo, true);
    }
    if (ucs_unlikely(ret != 0)) {
        ucs_mpool_put(desc);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    ep->outstanding++;
    iface->tx.outstanding++;

    return UCS_INPROGRESS;
}

ucs_status_t uct_cxi_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                        uint64_t swap, uint64_t remote_addr,
                                        uct_rkey_t rkey, uint64_t *result,
                                        uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_cswap_common(tl_ep, compare, swap, remote_addr,
                                          rkey, result, comp,
                                          C_AMO_TYPE_UINT64_T, sizeof(uint64_t));
}

ucs_status_t uct_cxi_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                        uint32_t swap, uint64_t remote_addr,
                                        uct_rkey_t rkey, uint32_t *result,
                                        uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_cswap_common(tl_ep, (uint64_t)compare,
                                          (uint64_t)swap, remote_addr,
                                          rkey, result, comp,
                                          C_AMO_TYPE_UINT32_T, sizeof(uint32_t));
}
