/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI Atomic Memory Operation declarations.
 *
 * All AMOs use restricted-mode IDC commands (c_cstate_cmd + c_idc_amo_cmd)
 * targeting the same catch-all RMA LE (pid_offset = LAC).  The NIC performs
 * the atomic read-modify-write at the target's memory location.
 *
 * Post (non-fetching): C_EVENT_ACK on completion.
 * Fetch / CSWAP:       C_EVENT_REPLY when result is DMA'd to local buffer.
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
