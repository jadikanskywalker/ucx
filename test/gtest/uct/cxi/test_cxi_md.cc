/**
 * CXI memory-domain unit tests.
 * Modeled after test/gtest/uct/ib/test_ib_md.cc.
 *
 * Hardware guard: uct_cxi_query_md_resources() returns an empty list when
 * SLINGSHOT_SVC_IDS is not set (single-node job or non-Slingshot system).
 * enum_mds("cxi") therefore returns an empty vector, and
 * INSTANTIATE_TEST_SUITE_P produces zero instances — tests are silently
 * skipped without any explicit UCS_TEST_SKIP_R call.  This mirrors the
 * IB transport's guard on HAVE_IB device presence.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <uct/api/uct.h>
#include <uct/cxi/base/cxi_md.h>
#include <common/test.h>
#include <uct/test_md.h>

#include "test_cxi_md.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>


/* -------------------------------------------------------------------------
 * Fixture implementation
 * -------------------------------------------------------------------------
 */

void test_cxi_md::init()
{
    test_md::init();
    /* No CXI-specific compile-time flags to save at Phase 1. */
}

const uct_cxi_md_t &test_cxi_md::cxi_md() const
{
    return *ucs_derived_of(md(), uct_cxi_md_t);
}

int test_cxi_md::env_svc_id(unsigned dev_id) const
{
    const char *env = getenv("SLINGSHOT_SVC_IDS");
    if (env == NULL) {
        return -1;
    }

    char *dup = strdup(env);
    if (dup == NULL) {
        return -1;
    }

    int      svc_id = -1;
    unsigned idx    = 0;

    for (char *tok = strtok(dup, ","); tok != NULL;
         tok = strtok(NULL, ","), idx++) {
        if (idx == dev_id) {
            svc_id = atoi(tok);
            break;
        }
    }

    free(dup);
    return svc_id;
}

uint16_t test_cxi_md::env_vni() const
{
    const char *env = getenv("SLINGSHOT_VNIS");
    if (env == NULL) {
        return 0;
    }

    char *dup = strdup(env);
    if (dup == NULL) {
        return 0;
    }

    uint16_t vni = 0;
    char *tok    = strtok(dup, ",");

    if (tok != NULL) {
        vni = (uint16_t)atoi(tok);
    }

    free(dup);
    return vni;
}


/* -------------------------------------------------------------------------
 * Test cases
 * -------------------------------------------------------------------------
 */

/*
 * Verify that the device descriptor fields are populated from real hardware
 * after md_open calls cxil_open_device and cxil_alloc_lni.
 */
UCS_TEST_P(test_cxi_md, device_info)
{
    const uct_cxi_md_t &m = cxi_md();

    /* Name must match the MD name supplied by the test parameter. */
    EXPECT_STREQ(GetParam().md_name.c_str(), m.device.name);

    /* NID 0 is never a valid Slingshot NIC address. */
    EXPECT_NE(0u, m.device.nid);

    /* dev_id must be parseable from "cxiN". */
    unsigned expected_dev_id;
    ASSERT_EQ(1, sscanf(m.device.name, "cxi%u", &expected_dev_id));
    EXPECT_EQ(expected_dev_id, m.device.dev_id);

    /* Hardware handles must be non-null after a successful open. */
    EXPECT_NE(nullptr, m.cxi_dev);
    EXPECT_NE(nullptr, m.cxi_lni);
}

/*
 * Verify that the svc_id and VNI recorded in the MD match the values the
 * SLURM Slingshot plugin injected into SLINGSHOT_SVC_IDS and SLINGSHOT_VNIS.
 * Also checks that the LNI was assigned a non-zero ID by the kernel.
 */
UCS_TEST_P(test_cxi_md, lni_credentials)
{
    const uct_cxi_md_t &m  = cxi_md();
    int                 exp_svc = env_svc_id(m.device.dev_id);
    uint16_t            exp_vni = env_vni();

    ASSERT_GE(exp_svc, 0) << "SLINGSHOT_SVC_IDS missing or too short";
    ASSERT_NE(0, exp_vni) << "SLINGSHOT_VNIS missing or zero";

    EXPECT_EQ((uint32_t)exp_svc, m.svc_id);
    EXPECT_EQ(exp_vni,           m.vni);

    /* A successfully allocated LNI always has a non-zero kernel-assigned ID. */
    EXPECT_NE(0u, m.cxi_lni->id);
}

/*
 * Register a small (4 KB) host buffer and deregister it.
 * Validates the basic cxil_map / cxil_unmap round-trip.
 */
UCS_TEST_P(test_cxi_md, reg_small)
{
    static const size_t  size = 4 * UCS_KBYTE;
    std::vector<uint8_t> buf(size);
    uct_mem_h            memh;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh));
    EXPECT_TRUE(memh != UCT_MEM_HANDLE_NULL);

    uct_md_mem_dereg_params_t params;
    params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    params.memh       = memh;
    EXPECT_UCS_OK(uct_md_mem_dereg_v2(md(), &params));
}

/*
 * Register a large (4 MB) host buffer — exercises multi-page pinning
 * and verifies the ATU mapping covers the full range.
 */
UCS_TEST_P(test_cxi_md, reg_large)
{
    static const size_t  size = 4 * UCS_MBYTE;
    std::vector<uint8_t> buf(size);
    uct_mem_h            memh;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh));
    EXPECT_TRUE(memh != UCT_MEM_HANDLE_NULL);

    uct_md_mem_dereg_params_t params;
    params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    params.memh       = memh;
    EXPECT_UCS_OK(uct_md_mem_dereg_v2(md(), &params));
}

/*
 * Register a buffer, pack the rkey, and inspect the raw uct_cxi_rkey_t
 * fields.  Verifies that:
 *   nid  == the MD's own NIC address
 *   iova != 0  (NIC-visible base address assigned by the ATU)
 *   lac  != 0  (memory access class — 0 is reserved in CXI hardware)
 */
UCS_TEST_P(test_cxi_md, rkey_pack)
{
    static const size_t  size = UCS_MBYTE;
    std::vector<uint8_t> buf(size);
    uct_mem_h            memh;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh));

    std::string               rkey_buf(md_attr().rkey_packed_size, '\0');
    uct_md_mkey_pack_params_t pack_params;
    pack_params.field_mask = 0;
    ASSERT_UCS_OK(uct_md_mkey_pack_v2(md(), memh, buf.data(), size,
                                      &pack_params, &rkey_buf[0]));

    const uct_cxi_rkey_t *rkey =
            reinterpret_cast<const uct_cxi_rkey_t *>(rkey_buf.data());

    EXPECT_EQ(cxi_md().device.nid, rkey->nid);
    EXPECT_NE((uint64_t)0, rkey->iova);
    EXPECT_NE(0u, (unsigned)rkey->lac);

    uct_md_mem_dereg_params_t dereg_params;
    dereg_params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    dereg_params.memh       = memh;
    EXPECT_UCS_OK(uct_md_mem_dereg_v2(md(), &dereg_params));
}

/*
 * Full pack → unpack → verify → release cycle.
 *
 * uct_rkey_unpack() stores a malloc'd uct_cxi_rkey_t* as bundle.rkey
 * (cast to uintptr_t).  We cast it back to verify the fields survived the
 * serialisation round-trip intact.
 */
UCS_TEST_P(test_cxi_md, rkey_roundtrip)
{
    static const size_t  size = UCS_KBYTE;
    std::vector<uint8_t> buf(size);
    uct_mem_h            memh;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh));

    std::string               rkey_buf(md_attr().rkey_packed_size, '\0');
    uct_md_mkey_pack_params_t pack_params;
    pack_params.field_mask = 0;
    ASSERT_UCS_OK(uct_md_mkey_pack_v2(md(), memh, buf.data(), size,
                                      &pack_params, &rkey_buf[0]));

    uct_rkey_bundle_t bundle;
    ASSERT_UCS_OK(uct_rkey_unpack(GetParam().component, &rkey_buf[0], &bundle));

    const uct_cxi_rkey_t *unpacked =
            reinterpret_cast<const uct_cxi_rkey_t *>(
                    reinterpret_cast<void *>((uintptr_t)bundle.rkey));

    EXPECT_EQ(cxi_md().device.nid, unpacked->nid);
    EXPECT_NE((uint64_t)0, unpacked->iova);
    EXPECT_NE(0u, (unsigned)unpacked->lac);

    EXPECT_UCS_OK(uct_rkey_release(GetParam().component, &bundle));

    uct_md_mem_dereg_params_t dereg_params;
    dereg_params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    dereg_params.memh       = memh;
    EXPECT_UCS_OK(uct_md_mem_dereg_v2(md(), &dereg_params));
}

/*
 * Verify the capability flags and packed rkey size reported by
 * uct_cxi_md_query.  These control how UCX upper layers interact with
 * the CXI memory domain.
 */
UCS_TEST_P(test_cxi_md, md_query_flags)
{
    const uint64_t required = UCT_MD_FLAG_REG      |
                              UCT_MD_FLAG_NEED_MEMH |
                              UCT_MD_FLAG_NEED_RKEY;

    EXPECT_EQ(required, md_attr().flags & required);
    EXPECT_EQ(sizeof(uct_cxi_rkey_t), md_attr().rkey_packed_size);
    EXPECT_NE(0u, (unsigned)(md_attr().reg_mem_types &
                             UCS_BIT(UCS_MEMORY_TYPE_HOST)));
}


_UCT_MD_INSTANTIATE_TEST_CASE(test_cxi_md, cxi)
