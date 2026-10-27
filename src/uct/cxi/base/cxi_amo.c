/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI atomic memory operations: restricted-mode IDC commands (c_cstate_cmd,
 * then c_idc_amo_cmd) to the target's catch-all RMA LE.
 *
 * Post (non-fetching): tracked by the ep alone, ACK. Returns UCS_OK.
 * Fetch / CSWAP:       a desc from desc_pool receives the result in its data
 *                      area (REPLY); the completion handler copies it out.
 *                      Returns UCS_INPROGRESS.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cxi_amo.h"
#include "cxi_iface.h"
#include "cxi_md.h"

#include <uct/base/uct_iface.h>
#include <ucs/debug/log.h>

#include <cassini_user_defs.h>
#include <cxi_prov_hw.h>

#include <string.h>


/* clang-format off */
static const uint8_t uct_cxi_amo_op_table[] = {
    [UCT_ATOMIC_OP_ADD]  = C_AMO_OP_SUM,
    [UCT_ATOMIC_OP_AND]  = C_AMO_OP_BAND,
    [UCT_ATOMIC_OP_OR]   = C_AMO_OP_BOR,
    [UCT_ATOMIC_OP_XOR]  = C_AMO_OP_BXOR,
    [UCT_ATOMIC_OP_SWAP] = C_AMO_OP_CSWAP,
};
/* clang-format on */

/* Copy the result out only on success: otherwise the buffer was not written. */
static void uct_cxi_amo_fetch_comp(uct_cxi_send_op_t *op, ucs_status_t status)
{
    uct_cxi_send_desc_t *desc = (uct_cxi_send_desc_t*)op;

    if (status == UCS_OK) {
        memcpy(desc->unpack_arg, desc + 1, desc->length);
    }

    if (op->comp != NULL) {
        uct_invoke_completion(op->comp, status);
    }

    ucs_mpool_put(desc);
}

/*
 * Emit \a cstate (with user_ptr and write_lac set by the caller) and \a amo,
 * ring, and account the op. UCS_ERR_NO_RESOURCE if the command queue is full.
 */
static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_amo_issue(
        uct_cxi_ep_t *ep, uct_cxi_iface_t *iface, const uct_cxi_rkey_t *rkey_p,
        uint64_t remote_addr, struct c_cstate_cmd *cstate,
        struct c_idc_amo_cmd *amo, bool fetching)
{
    int ret;

    cstate->event_send_disable = 1;
    cstate->restricted         = 1;
    cstate->index_ext          = ep->dfa_rma_idx_ext[rkey_p->lac];
    cstate->eq                 = iface->tx_eq.evtq->eqn;

    ret = cxi_cq_emit_c_state(iface->tx.cmdq, cstate);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, "ep_atomic", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    amo->idc_header.dfa           = ep->dfa_rma[rkey_p->lac];
    amo->idc_header.remote_offset = rkey_p->iova + remote_addr;

    ret = cxi_cq_emit_idc_amo(iface->tx.cmdq, amo, fetching);
    if (ucs_unlikely(ret != 0)) {
        uct_cxi_tx_emit_error(ep, "ep_atomic", ret);
        return UCS_ERR_NO_RESOURCE;
    }

    cxi_cq_ring(iface->tx.cmdq);
    uct_cxi_ep_tx_commit(ep, iface);
    return UCS_OK;
}

/* A desc whose data area receives the result, copied to \a result on REPLY. */
static UCS_F_ALWAYS_INLINE uct_cxi_send_desc_t *
uct_cxi_amo_desc_get(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                     uct_completion_t *comp, void *result, size_t result_size)
{
    uct_cxi_send_desc_t *desc = ucs_mpool_get(&iface->tx.desc_pool);

    if (ucs_unlikely(desc == NULL)) {
        UCT_TL_IFACE_STAT_TX_NO_DESC(&iface->super);
        return NULL;
    }

    uct_cxi_send_op_set(&desc->op, ep, comp, uct_cxi_amo_fetch_comp);
    desc->unpack_arg = result;
    desc->length     = result_size;
    return desc;
}

/* Issue a fetching \a amo with its result in \a desc; frees it on failure. */
static UCS_F_ALWAYS_INLINE ucs_status_t
uct_cxi_amo_fetch_issue(uct_cxi_ep_t *ep, uct_cxi_iface_t *iface,
                        const uct_cxi_rkey_t *rkey_p, uint64_t remote_addr,
                        uct_cxi_send_desc_t *desc, struct c_idc_amo_cmd *amo)
{
    struct c_cstate_cmd cstate = {};
    ucs_status_t status;

    cstate.write_lac = desc->lac;
    cstate.user_ptr  = (uint64_t)(uintptr_t)desc;
    amo->local_addr  = desc->iova;

    status = uct_cxi_amo_issue(ep, iface, rkey_p, remote_addr, &cstate, amo,
                               true);
    if (ucs_unlikely(status != UCS_OK)) {
        ucs_mpool_put(desc);
        return status;
    }

    return UCS_INPROGRESS;
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_ep_atomic_post_common(
        uct_ep_h tl_ep, uct_atomic_op_t opcode, uint64_t value,
        uint64_t remote_addr, uct_rkey_t rkey, uint8_t amo_type)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_cstate_cmd cstate   = {};
    struct c_idc_amo_cmd amo     = {};

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    cstate.user_ptr = uct_cxi_ep_short_user_ptr(ep);

    amo.atomic_op   = uct_cxi_amo_op_table[opcode];
    amo.atomic_type = amo_type;
    amo.op1_word1   = value;

    return uct_cxi_amo_issue(ep, iface, rkey_p, remote_addr, &cstate, &amo,
                             false);
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
    return uct_cxi_ep_atomic_post_common(tl_ep, opcode, value, remote_addr,
                                         rkey, C_AMO_TYPE_UINT32_T);
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_ep_atomic_fetch_common(
        uct_ep_h tl_ep, uct_atomic_op_t opcode, uint64_t value, void *result,
        uint64_t remote_addr, uct_rkey_t rkey, uct_completion_t *comp,
        uint8_t amo_type, size_t result_size)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_idc_amo_cmd amo     = {};
    uct_cxi_send_desc_t *desc;

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = uct_cxi_amo_desc_get(ep, iface, comp, result, result_size);
    if (ucs_unlikely(desc == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    amo.atomic_op   = uct_cxi_amo_op_table[opcode];
    amo.atomic_type = amo_type;
    amo.op1_word1   = value;

    if (opcode == UCT_ATOMIC_OP_SWAP) {
        amo.cswap_op  = C_AMO_OP_CSWAP_NE;
        amo.op2_word1 = value;
    }

    return uct_cxi_amo_fetch_issue(ep, iface, rkey_p, remote_addr, desc, &amo);
}

ucs_status_t uct_cxi_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint64_t value, uint64_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                          remote_addr, rkey, comp,
                                          C_AMO_TYPE_UINT64_T, sizeof(*result));
}

ucs_status_t uct_cxi_ep_atomic32_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint32_t value, uint32_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                          remote_addr, rkey, comp,
                                          C_AMO_TYPE_UINT32_T, sizeof(*result));
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_cxi_ep_atomic_cswap_common(
        uct_ep_h tl_ep, uint64_t compare, uint64_t swap, uint64_t remote_addr,
        uct_rkey_t rkey, void *result, uct_completion_t *comp, uint8_t amo_type,
        size_t result_size)
{
    uct_cxi_ep_t *ep             = ucs_derived_of(tl_ep, uct_cxi_ep_t);
    uct_cxi_iface_t *iface       = uct_cxi_ep_iface(ep);
    const uct_cxi_rkey_t *rkey_p = (const uct_cxi_rkey_t*)(uintptr_t)rkey;
    struct c_idc_amo_cmd amo     = {};
    uct_cxi_send_desc_t *desc;

    if (uct_cxi_iface_tx_blocked(iface, NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    desc = uct_cxi_amo_desc_get(ep, iface, comp, result, result_size);
    if (ucs_unlikely(desc == NULL)) {
        return UCS_ERR_NO_RESOURCE;
    }

    amo.atomic_op   = C_AMO_OP_CSWAP;
    amo.atomic_type = amo_type;
    amo.cswap_op    = C_AMO_OP_CSWAP_EQ;
    amo.op1_word1   = swap;
    amo.op2_word1   = compare;

    return uct_cxi_amo_fetch_issue(ep, iface, rkey_p, remote_addr, desc, &amo);
}

ucs_status_t uct_cxi_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                       uint64_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint64_t *result,
                                       uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_cswap_common(tl_ep, compare, swap, remote_addr,
                                          rkey, result, comp,
                                          C_AMO_TYPE_UINT64_T, sizeof(*result));
}

ucs_status_t uct_cxi_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                       uint32_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint32_t *result,
                                       uct_completion_t *comp)
{
    return uct_cxi_ep_atomic_cswap_common(tl_ep, compare, swap, remote_addr,
                                          rkey, result, comp,
                                          C_AMO_TYPE_UINT32_T, sizeof(*result));
}
