/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT endpoint unit tests — EP lifecycle only.
 *
 * Tests here cover ep_create / ep_destroy and ep_flush semantics without
 * posting any data.  Data-movement tests (ep_put_zcopy, ep_get_zcopy) live
 * in test_cxi_rma.cc where they can share the same fixture.
 *
 * Hardware guard: when SLINGSHOT_SVC_IDS is unset, uct_cxi_query_md_resources
 * returns an empty list, enum_resources("cxi") produces zero test instances,
 * and all tests are silently skipped.
 *
 * Single-node loopback: CXI hardware supports intra-NIC loopback, so both
 * entities in a test can share the same physical NIC.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "test_cxi_rma.h"


/* -------------------------------------------------------------------------
 * Fixture
 * -------------------------------------------------------------------------
 */

/**
 * test_cxi_ep — endpoint lifecycle fixture.
 *
 * Inherits the two-entity setup from test_cxi_rma_base.  No additional
 * state is needed for pure lifecycle tests.
 */
class test_cxi_ep : public test_cxi_rma_base {};


/* -------------------------------------------------------------------------
 * Test cases
 * -------------------------------------------------------------------------
 */

/**
 * Verify that an EP can be created to the receiver's iface and destroyed.
 */
UCS_TEST_P(test_cxi_ep, ep_create_destroy)
{
    sender().connect_to_iface(0, receiver());

    uct_ep_h ep = sender().ep(0);
    EXPECT_NE((uct_ep_h)NULL, ep);

    ucs_debug("cxi ep_create_destroy: ep %p", ep);
}

/**
 * Verify that ep_flush returns UCS_OK immediately when no sends are posted.
 */
UCS_TEST_P(test_cxi_ep, ep_flush_empty)
{
    sender().connect_to_iface(0, receiver());

    uct_ep_h     ep     = sender().ep(0);
    ucs_status_t status = uct_ep_flush(ep, 0, NULL);

    ASSERT_EQ(UCS_OK, status)
            << "ep_flush with no outstanding ops must return UCS_OK";
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_ep, cxi)
