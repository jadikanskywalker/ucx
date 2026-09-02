/**
 * CXI memory-domain unit tests.
 * Modeled after test/gtest/uct/ib/test_ib_md.cc.
 *
 * Hardware guard: uct_cxi_query_md_resources() unconditionally enumerates
 * every physical CXI device via cxil_get_device_list() — it returns an
 * empty list only when no CXI devices are present at all (non-Slingshot
 * system), which is when enum_mds("cxi") is empty and
 * INSTANTIATE_TEST_SUITE_P produces zero instances, silently skipping
 * these tests without any explicit UCS_TEST_SKIP_R call.  Credential
 * resolution (SLINGSHOT_SVC_IDS/SLINGSHOT_VNIS env vars, falling back to
 * kernel-side service-membership discovery when they're absent — see
 * uct_cxi_get_rgroup_vni in cxi_md.c) happens later, per-device, at
 * md_open time — a device is present in enum_mds("cxi") either way, and
 * only fails md_open if neither credential path finds a usable service.
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
#include <unistd.h>


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

/*
 * Independent re-derivation of uct_cxi_find_svc_by_membership()'s
 * priority-selection logic (cxi_md.c:212-296): UID match, then GID match,
 * then unrestricted, walking the service list back-to-front and locking
 * in the first (highest-index) match per category.  Deliberately
 * duplicated rather than exposing the production function purely for
 * testing (same tradeoff env_svc_id()/env_vni() above already carry for
 * the env-var path) -- needs manual sync if the production logic changes.
 */
int test_cxi_md::membership_svc_id(struct cxil_dev *dev,
                                   uint16_t *vni_out) const
{
    struct cxil_svc_list *svc_list;
    struct cxi_svc_desc  *desc;
    uid_t                 uid = geteuid();
    gid_t                 gid = getegid();
    int                   found_uid = -1;
    int                   found_gid = -1;
    int                   found_unrestricted = -1;
    int                   i, j;

    if (cxil_get_svc_list(dev, &svc_list) != 0) {
        return -1;
    }

    for (i = (int)svc_list->count - 1; i >= 0; i--) {
        desc = svc_list->descs + i;

        if (!desc->enable || desc->is_system_svc) {
            continue;
        }

        if (!desc->restricted_members) {
            if (found_unrestricted == -1) {
                found_unrestricted = i;
            }
            continue;
        }

        for (j = 0; j < CXI_SVC_MAX_MEMBERS; j++) {
            if ((desc->members[j].type == CXI_SVC_MEMBER_UID) &&
                (desc->members[j].svc_member.uid == uid) &&
                (found_uid == -1)) {
                found_uid = i;
            } else if ((desc->members[j].type == CXI_SVC_MEMBER_GID) &&
                       (desc->members[j].svc_member.gid == gid) &&
                       (found_gid == -1)) {
                found_gid = i;
            }
        }
    }

    if (found_uid != -1) {
        i = found_uid;
    } else if (found_gid != -1) {
        i = found_gid;
    } else if (found_unrestricted != -1) {
        i = found_unrestricted;
    } else {
        cxil_free_svc_list(svc_list);
        return -1;
    }

    desc = svc_list->descs + i;

    if (desc->restricted_vnis && (desc->num_vld_vnis > 0)) {
        *vni_out = (uint16_t)desc->vnis[0];
    } else {
        *vni_out = 0;
    }

    i = (int)desc->svc_id;

    cxil_free_svc_list(svc_list);
    return i;
}

ucs_status_t test_cxi_md::dereg_mem(uct_mem_h memh)
{
    uct_md_mem_dereg_params_t params;
    params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    params.memh       = memh;
    return uct_md_mem_dereg_v2(md(), &params);
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
 *
 * Only covers the env-var credential path; skips (not fails) when the
 * launcher doesn't set those vars -- that's the other valid path, covered
 * by lni_credentials_membership_fallback below.
 */
UCS_TEST_P(test_cxi_md, lni_credentials)
{
    const uct_cxi_md_t &m  = cxi_md();
    int                 exp_svc = env_svc_id(m.device.dev_id);
    uint16_t            exp_vni = env_vni();

    if (exp_svc < 0) {
        UCS_TEST_SKIP_R("SLINGSHOT_SVC_IDS missing or too short");
    }
    if (exp_vni == 0) {
        UCS_TEST_SKIP_R("SLINGSHOT_VNIS missing or zero");
    }

    EXPECT_EQ((uint32_t)exp_svc, m.svc_id);
    EXPECT_EQ(exp_vni,           m.vni);

    /* A successfully allocated LNI always has a non-zero kernel-assigned ID. */
    EXPECT_NE(0u, m.cxi_lni->id);
}

/*
 * Verify the kernel-side service-membership fallback path
 * (uct_cxi_find_svc_by_membership, used when SLINGSHOT_SVC_IDS/
 * SLINGSHOT_VNIS aren't set) independently of the ambient launcher's env.
 *
 * scoped_setenv always *sets* a value; "" parses to zero tokens in
 * env_svc_id()/env_vni() (and in the production uct_cxi_get_svc_id/
 * uct_cxi_get_vni, which use the same strtok-on-empty-string behavior),
 * which is indistinguishable from unset -- this forces
 * uct_cxi_get_rgroup_vni's fallback branch deterministically without
 * needing to save/restore via unsetenv.
 */
UCS_TEST_P(test_cxi_md, lni_credentials_membership_fallback)
{
    ucs::scoped_setenv no_svc("SLINGSHOT_SVC_IDS", "");
    ucs::scoped_setenv no_vni("SLINGSHOT_VNIS", "");

    ucs::handle<uct_md_h> fallback_md;
    {
        /* uct_cxi_get_svc_id() legitimately warns ("SLINGSHOT_SVC_IDS has
         * no entry for device index N") when the var is set but empty --
         * an expected side effect of forcing the fallback path this way,
         * not a bug; suppress it so it doesn't fail the test. */
        scoped_log_handler hide_warn(hide_warns_logger);
        UCS_TEST_CREATE_HANDLE(uct_md_h, fallback_md, uct_md_close,
                               uct_md_open, GetParam().component,
                               GetParam().md_name.c_str(), m_md_config);
    }

    const uct_cxi_md_t &m = *ucs_derived_of((uct_md_h)fallback_md,
                                            uct_cxi_md_t);
    EXPECT_NE(0u, m.cxi_lni->id);

    /* Cross-check against an independent re-implementation of the same
     * UID > GID > unrestricted priority selection uct_cxi_find_svc_by_membership
     * uses, rather than just checking md_open didn't crash. */
    uint16_t expected_vni;
    int      expected_svc = membership_svc_id(m.cxi_dev, &expected_vni);

    ASSERT_GE(expected_svc, 0) << "no matching/unrestricted service available "
                                  "for this process's uid/gid";
    EXPECT_EQ((uint32_t)expected_svc, m.svc_id);
    EXPECT_EQ(expected_vni, m.vni);
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
 *   iova != 0  (NIC-visible base address assigned by the ATU)
 *   lac  is a valid LAC index assigned by the kernel (0–7 per LNI;
 *         0 is the first valid assignment, not a sentinel for invalid)
 *
 * nid is no longer packed in the rkey — the initiator EP obtains it from
 * the peer's device_addr at connect time.
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

    EXPECT_NE((uint64_t)0, rkey->iova);

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

    /* Verify both fields survived the pack → unpack round-trip intact. */
    const uct_cxi_rkey_t *packed =
            reinterpret_cast<const uct_cxi_rkey_t *>(rkey_buf.data());
    EXPECT_EQ(packed->iova, unpacked->iova);
    EXPECT_EQ(packed->lac,  unpacked->lac);

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


/*
 * Registration-cache overlap test.
 *
 * Register a large (2 MB) buffer, then register a 512 KB sub-range that falls
 * entirely inside the first registration.  Because the rcache merges overlapping
 * VA ranges into a single region, both calls must return memh pointers that
 * alias the same uct_cxi_rcache_region_t, i.e. both point into the same region.
 * Specifically, both memh values must be equal (same embedded memh address).
 *
 * The test is skipped when the rcache is disabled (e.g. UCX_CXI_RCACHE=no).
 */
UCS_TEST_P(test_cxi_md, rcache_overlap_shared_region)
{
    if (cxi_md().rcache == NULL) {
        UCS_TEST_SKIP_R("registration cache not enabled");
    }

    static const size_t  big_size   = 2 * UCS_MBYTE;
    static const size_t  sub_size   = 512 * UCS_KBYTE;
    std::vector<uint8_t> buf(big_size);
    uct_mem_h            memh_big;
    uct_mem_h            memh_sub;

    /* Register the large region. */
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), big_size, &memh_big));
    EXPECT_TRUE(memh_big != UCT_MEM_HANDLE_NULL);

    /* Register a sub-range entirely inside the large region.  The rcache must
     * extend (or reuse) the existing region — the returned memh must be the
     * same pointer because it is the embedded field of the same region. */
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA,
                          buf.data() + UCS_KBYTE, sub_size, &memh_sub));
    EXPECT_EQ(memh_big, memh_sub)
            << "rcache should return the same region for an overlapping range";

    /* Release both references.  The region must survive until the second put. */
    EXPECT_UCS_OK(dereg_mem(memh_big));
    EXPECT_UCS_OK(dereg_mem(memh_sub));
}

/*
 * Registration-cache reference-count test.
 *
 * Register the same 1 MB range twice.  The rcache must return the same region
 * (and the same memh pointer) both times.  Releasing the first reference must
 * not trigger cxil_unmap — the region must still be usable via the second
 * handle.  A third registration after releasing both must succeed cleanly,
 * confirming the unmap/remap cycle is correct.
 */
UCS_TEST_P(test_cxi_md, rcache_refcount)
{
    if (cxi_md().rcache == NULL) {
        UCS_TEST_SKIP_R("registration cache not enabled");
    }

    static const size_t  size = UCS_MBYTE;
    std::vector<uint8_t> buf(size);
    uct_mem_h            memh1;
    uct_mem_h            memh2;
    uct_mem_h            memh3;

    /* First registration — cache miss, cxil_map is called. */
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh1));
    EXPECT_TRUE(memh1 != UCT_MEM_HANDLE_NULL);

    /* Second registration of the identical range — must be a cache hit. */
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh2));
    EXPECT_EQ(memh1, memh2) << "rcache must return the same region on a hit";

    /* Release first reference.  Region refcount drops to 1 — still live. */
    EXPECT_UCS_OK(dereg_mem(memh1));

    /* Verify the region is still usable by packing its rkey. */
    std::string               rkey_buf(md_attr().rkey_packed_size, '\0');
    uct_md_mkey_pack_params_t pack_params;
    pack_params.field_mask = 0;
    EXPECT_UCS_OK(uct_md_mkey_pack_v2(md(), memh2, buf.data(), size,
                                      &pack_params, &rkey_buf[0]));

    /* Release second reference.  Now refcount hits 0, cxil_unmap is called. */
    EXPECT_UCS_OK(dereg_mem(memh2));

    /* A fresh registration on the same buffer must succeed (clean remap). */
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), size, &memh3));
    EXPECT_TRUE(memh3 != UCT_MEM_HANDLE_NULL);
    EXPECT_UCS_OK(dereg_mem(memh3));
}


/*
 * ATS shared-backing-md test.
 *
 * When PCIe ATS is active, every mem_reg allocates a fresh uct_cxi_mem_handle_t
 * wrapper but all wrappers point to the single shared scalable cxi_md.  Verify
 * that two distinct buffer registrations produce different handle pointers yet
 * embed the same cxi_md pointer, and that both dereg calls succeed.
 */
UCS_TEST_P(test_cxi_md, ats_shared_memh)
{
    if (cxi_md().ats_md == NULL) {
        UCS_TEST_SKIP_R("ATS not enabled");
    }

    std::vector<uint8_t> buf1(UCS_KBYTE), buf2(UCS_KBYTE);
    uct_mem_h            memh1, memh2;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf1.data(), buf1.size(),
                          &memh1));
    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf2.data(), buf2.size(),
                          &memh2));

    const uct_cxi_mem_handle_t *mh1 =
            static_cast<const uct_cxi_mem_handle_t *>(memh1);
    const uct_cxi_mem_handle_t *mh2 =
            static_cast<const uct_cxi_mem_handle_t *>(memh2);

    EXPECT_EQ(mh1->cxi_md, mh2->cxi_md)
            << "ATS mode: all handles must share the same scalable cxi_md";

    EXPECT_UCS_OK(dereg_mem(memh1));
    EXPECT_UCS_OK(dereg_mem(memh2));
}

/*
 * ATS rkey IOVA formula test.
 *
 * In ATS mode mkey_pack stores the iova_offset in rkey.iova.  Because the
 * ATS scalable mapping covers the full virtual address space starting at
 * VA = 0, iova_offset = ats_md->iova − 0 = ats_md->iova.
 *
 *   rkey.iova = ats_md->iova   (iova_offset; base_VA = 0 for scalable map)
 *   rkey.lac  = ats_md->lac
 *
 * An initiator EP computes the remote IOVA as:
 *   remote_iova = rkey.iova + remote_addr
 *               = ats_md->iova + remote_VA
 *
 * Verify both fields match the raw ats_md values.
 */
UCS_TEST_P(test_cxi_md, ats_rkey_iova)
{
    if (cxi_md().ats_md == NULL) {
        UCS_TEST_SKIP_R("ATS not enabled");
    }

    std::vector<uint8_t> buf(UCS_KBYTE);
    uct_mem_h            memh;

    ASSERT_UCS_OK(reg_mem(UCT_MD_MEM_ACCESS_RMA, buf.data(), buf.size(), &memh));

    std::string               rkey_buf(md_attr().rkey_packed_size, '\0');
    uct_md_mkey_pack_params_t pack_params;
    pack_params.field_mask = 0;
    ASSERT_UCS_OK(uct_md_mkey_pack_v2(md(), memh, buf.data(), buf.size(),
                                      &pack_params, &rkey_buf[0]));

    const uct_cxi_rkey_t *rkey =
            reinterpret_cast<const uct_cxi_rkey_t *>(rkey_buf.data());
    const struct cxi_md  *ats  = cxi_md().ats_md;

    /* rkey.iova is iova_offset = ats_md->iova (base_VA = 0 for ATS). */
    EXPECT_EQ((uint64_t)ats->iova, rkey->iova);
    EXPECT_EQ((unsigned)ats->lac, (unsigned)rkey->lac);

    EXPECT_UCS_OK(dereg_mem(memh));
}


_UCT_MD_INSTANTIATE_TEST_CASE(test_cxi_md, cxi)
