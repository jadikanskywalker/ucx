/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI RMA operation declarations.
 */

#ifndef UCT_CXI_RMA_H
#define UCT_CXI_RMA_H

#include "cxi_ep.h"
#include <uct/api/uct.h>


ucs_status_t uct_cxi_ep_get_short(uct_ep_h tl_ep, void *buffer,
                                   unsigned length, uint64_t remote_addr,
                                   uct_rkey_t rkey);

ucs_status_t uct_cxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                   unsigned length, uint64_t remote_addr,
                                   uct_rkey_t rkey);

ssize_t uct_cxi_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                              void *arg, uint64_t remote_addr, uct_rkey_t rkey);

ucs_status_t uct_cxi_ep_get_bcopy(uct_ep_h tl_ep,
                                   uct_unpack_callback_t unpack_cb,
                                   void *arg, size_t length,
                                   uint64_t remote_addr, uct_rkey_t rkey,
                                   uct_completion_t *comp);

ucs_status_t uct_cxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                   size_t iovcnt, uint64_t remote_addr,
                                   uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_cxi_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                   size_t iovcnt, uint64_t remote_addr,
                                   uct_rkey_t rkey, uct_completion_t *comp);

#endif /* UCT_CXI_RMA_H */
