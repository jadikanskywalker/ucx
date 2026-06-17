/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI Active Message operation declarations.
 *
 * AM short: c_cstate_cmd (restricted=0) + c_idc_msg_hdr carrying
 *   [uint64_t header][payload] ≤ C_MAX_IDC_PAYLOAD_UNR = 192 B total.
 *   The 8-byte UCT header is packed inline before the user payload so the
 *   receiver gets a single contiguous buffer directly from rx_buf.
 *
 * AM bcopy: c_full_dma_cmd (restricted=0) to the remote AM OVERFLOW LE;
 *   the desc_pool bounce buffer is reused (same as RMA put_bcopy).
 *
 * RX: iface_progress handles C_EVENT_PUT from the AM PTE's OVERFLOW LE and
 *   dispatches to the callback registered via uct_iface_set_am_handler.
 */

#ifndef UCT_CXI_AM_H
#define UCT_CXI_AM_H

#include "cxi_ep.h"
#include <uct/api/uct.h>


ucs_status_t uct_cxi_ep_am_short(uct_ep_h ep, uint8_t id, uint64_t header,
                                  const void *payload, unsigned length);

ssize_t uct_cxi_ep_am_bcopy(uct_ep_h ep, uint8_t id,
                             uct_pack_callback_t pack_cb, void *arg,
                             unsigned flags);

#endif /* UCT_CXI_AM_H */
