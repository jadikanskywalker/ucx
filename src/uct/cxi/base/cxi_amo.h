/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI atomic memory operation declarations (see cxi_amo.c).
 */

#ifndef UCT_CXI_AMO_H
#define UCT_CXI_AMO_H

#include "cxi_ep.h"
#include <uct/api/uct.h>


ucs_status_t uct_cxi_ep_atomic64_post(uct_ep_h ep, uct_atomic_op_t opcode,
                                      uint64_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey);

ucs_status_t uct_cxi_ep_atomic32_post(uct_ep_h ep, uct_atomic_op_t opcode,
                                      uint32_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey);

ucs_status_t uct_cxi_ep_atomic64_fetch(uct_ep_h ep, uct_atomic_op_t opcode,
                                       uint64_t value, uint64_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_cxi_ep_atomic32_fetch(uct_ep_h ep, uct_atomic_op_t opcode,
                                       uint32_t value, uint32_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_cxi_ep_atomic_cswap64(uct_ep_h ep, uint64_t compare,
                                       uint64_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint64_t *result,
                                       uct_completion_t *comp);

ucs_status_t uct_cxi_ep_atomic_cswap32(uct_ep_h ep, uint32_t compare,
                                       uint32_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint32_t *result,
                                       uct_completion_t *comp);

#endif /* UCT_CXI_AMO_H */
