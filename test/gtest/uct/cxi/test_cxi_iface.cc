/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * CXI UCT interface unit tests.
 *
 * Covers the Phase-2 iface implementation: iface_open (implicit via the
 * fixture), iface_query, get_device_address, get_address, event_fd_get,
 * and is_reachable_v2.
 *
 * Hardware guard: uct_cxi_query_md_resources() returns an empty list when
 * SLINGSHOT_SVC_IDS is not set (single-node job or non-Slingshot system).
 * enum_resources("cxi") therefore produces zero test instances, and the
 * tests are silently skipped without any explicit UCS_TEST_SKIP_R call.
 * This mirrors the guard used by the MD tests.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <uct/api/uct.h>
#include <uct/api/v2/uct_v2.h>
#include <uct/cxi/base/cxi_iface.h>
#include <uct/cxi/base/cxi_md.h>
#include <common/test.h>
#include <uct/uct_test.h>

#include <string>


/* -------------------------------------------------------------------------
 * Fixture
 * -------------------------------------------------------------------------
 */

/**
 * CXI interface test fixture.
 *
 * Creates one entity (MD + worker + iface) at init time.  All tests use
 * get_entity() to access the open iface.
 */
class test_cxi_iface : public uct_test {
protected:
    void init() override
    {
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(0));
    }

    entity &get_entity()
    {
        return *m_entities.front();
    }

    /**
     * Type-safe accessor to the underlying CXI MD.
     * Mirrors cxi_md() in test_cxi_md.
     */
    const uct_cxi_md_t &cxi_md()
    {
        return *ucs_derived_of(m_entities.front()->md(), uct_cxi_md_t);
    }
};


/* -------------------------------------------------------------------------
 * Test cases
 * -------------------------------------------------------------------------
 */

/**
 * Verify the capability report from uct_cxi_iface_query.
 *
 * Phase 3: ep_put_zcopy is wired; the iface must advertise PUT_ZCOPY and
 * PENDING.  Bandwidth (200 Gb/s dedicated, 0 shared), latency (1500 ns
 * constant), and address-length fields are checked against the values
 * hard-coded in uct_cxi_iface_query.
 */
UCS_TEST_P(test_cxi_iface, iface_query)
{
    const uct_iface_attr_t &attr = get_entity().iface_attr();

    /* Address lengths must match the packed struct sizes. */
    EXPECT_EQ(sizeof(uct_cxi_device_addr_t), attr.device_addr_len);
    EXPECT_EQ(sizeof(uct_cxi_iface_addr_t),  attr.iface_addr_len);
    EXPECT_EQ(0u,                             attr.ep_addr_len);

    /*
     * Bandwidth: 200 Gb/s dedicated, zero shared.
     * Each Slingshot NIC belongs to one process — bandwidth is not divided.
     */
    EXPECT_DOUBLE_EQ(25000.0 * UCS_MBYTE, attr.bandwidth.dedicated);
    EXPECT_DOUBLE_EQ(0.0,                 attr.bandwidth.shared);

    /* Latency constant: 1500 ns. */
    EXPECT_DOUBLE_EQ(1500e-9, attr.latency.c);

    /* Phase 3: PUT_ZCOPY and PENDING must be advertised. */
    EXPECT_TRUE(attr.cap.flags & UCT_IFACE_FLAG_PUT_ZCOPY)
            << "cxi iface must advertise UCT_IFACE_FLAG_PUT_ZCOPY";
    EXPECT_TRUE(attr.cap.flags & UCT_IFACE_FLAG_PENDING)
            << "cxi iface must advertise UCT_IFACE_FLAG_PENDING";
    EXPECT_EQ(1u,        attr.cap.put.max_iov);
    EXPECT_EQ(0u,        attr.cap.put.min_zcopy);
}

/**
 * Verify that uct_cxi_iface_get_device_address returns the NIC address (NID)
 * that this iface's MD recorded at open time.
 *
 * A valid Slingshot NID is never 0; it must also match the value stored in
 * the MD so that EPs can verify connectivity at connect time.
 */
UCS_TEST_P(test_cxi_iface, get_device_address)
{
    std::string dev_buf(sizeof(uct_cxi_device_addr_t), '\0');
    uct_iface_h iface = get_entity().iface();

    ASSERT_UCS_OK(uct_iface_get_device_address(
                          iface, (uct_device_addr_t *)&dev_buf[0]));

    const uct_cxi_device_addr_t *dev_addr =
            reinterpret_cast<const uct_cxi_device_addr_t *>(dev_buf.data());

    /* NID 0 is not a valid Slingshot fabric address. */
    EXPECT_NE(0u, dev_addr->nid);

    /* Must match the NID recorded in the MD at open time. */
    EXPECT_EQ(cxi_md().device.nid, dev_addr->nid);
}

/**
 * Verify that uct_cxi_iface_get_address returns a valid pid.
 *
 * pid — CXI Port ID, range 0–510 (9-bit value assigned by the kernel when
 *       cxil_alloc_domain is called).
 *
 * The pid is the only field in uct_cxi_iface_addr_t; per-operation
 * pid_offsets (0 for RMA/LAC-0, UCT_CXI_PTE_TAG for tag, UCT_CXI_PTE_AM
 * for AM) are protocol constants added by the initiator when building the
 * DFA, so they are not exchanged in the iface address.
 */
UCS_TEST_P(test_cxi_iface, get_address)
{
    std::string iface_buf(sizeof(uct_cxi_iface_addr_t), '\0');
    uct_iface_h iface = get_entity().iface();

    ASSERT_UCS_OK(uct_iface_get_address(
                          iface, (uct_iface_addr_t *)&iface_buf[0]));

    const uct_cxi_iface_addr_t *addr =
            reinterpret_cast<const uct_cxi_iface_addr_t *>(iface_buf.data());

    /* CXI PIDs are 9-bit values in the range 0–510. */
    EXPECT_LE(addr->pid, 510u);

    UCS_TEST_MESSAGE << "cxi iface addr: pid=" << addr->pid;
}

/**
 * Verify that uct_cxi_iface_event_fd_get returns a valid file descriptor
 * backed by the cxil wait object.
 *
 * The wait object fd is used for interrupt-driven progress via epoll.
 * A non-negative fd confirms the kernel successfully allocated the interrupt
 * resource.
 */
UCS_TEST_P(test_cxi_iface, event_fd_get)
{
    int         fd    = -1;
    uct_iface_h iface = get_entity().iface();

    ASSERT_UCS_OK(uct_iface_event_fd_get(iface, &fd));
    EXPECT_GE(fd, 0);
}

/**
 * Verify that this iface considers itself reachable via uct_iface_is_reachable_v2.
 *
 * Obtains the iface's own device_addr and iface_addr, then calls
 * uct_iface_is_reachable_v2 with those addresses.  On a Slingshot fabric
 * all endpoints within the same VNI are network-reachable, so
 * self-reachability is the minimal sanity check for this function.
 */
UCS_TEST_P(test_cxi_iface, is_reachable_v2)
{
    const uct_iface_attr_t &attr  = get_entity().iface_attr();
    uct_iface_h             iface = get_entity().iface();

    std::string dev_buf(attr.device_addr_len, '\0');
    std::string iface_buf(attr.iface_addr_len, '\0');

    ASSERT_UCS_OK(uct_iface_get_device_address(
                          iface, (uct_device_addr_t *)&dev_buf[0]));
    ASSERT_UCS_OK(uct_iface_get_address(
                          iface, (uct_iface_addr_t *)&iface_buf[0]));

    char info_str[256] = "";

    uct_iface_is_reachable_params_t params;
    params.field_mask =
            UCT_IFACE_IS_REACHABLE_FIELD_DEVICE_ADDR        |
            UCT_IFACE_IS_REACHABLE_FIELD_IFACE_ADDR         |
            UCT_IFACE_IS_REACHABLE_FIELD_INFO_STRING        |
            UCT_IFACE_IS_REACHABLE_FIELD_INFO_STRING_LENGTH |
            UCT_IFACE_IS_REACHABLE_FIELD_DEVICE_ADDR_LENGTH |
            UCT_IFACE_IS_REACHABLE_FIELD_IFACE_ADDR_LENGTH;
    params.device_addr        = (uct_device_addr_t *)&dev_buf[0];
    params.device_addr_length = attr.device_addr_len;
    params.iface_addr         = (uct_iface_addr_t *)&iface_buf[0];
    params.iface_addr_length  = attr.iface_addr_len;
    params.info_string        = info_str;
    params.info_string_length = sizeof(info_str);

    EXPECT_TRUE(uct_iface_is_reachable_v2(iface, &params))
            << "CXI iface should be able to reach itself; info: " << info_str;
}


_UCT_INSTANTIATE_TEST_CASE(test_cxi_iface, cxi)
