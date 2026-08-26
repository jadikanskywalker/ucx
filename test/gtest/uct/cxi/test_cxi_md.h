/**
 * CXI memory-domain test fixture.
 * Modeled after test_ib_md in test/gtest/uct/ib/test_ib_md.cc.
 */

#ifndef UCT_CXI_TEST_MD_H
#define UCT_CXI_TEST_MD_H

#include <uct/cxi/base/cxi_md.h>
#include <uct/test_md.h>

#include <cstdlib>
#include <cstring>


class test_cxi_md : public test_md {
protected:
    void init() override;

    /* Type-safe accessor — mirrors ib_md() in test_ib_md. */
    const uct_cxi_md_t &cxi_md() const;

    /*
     * Parse SLINGSHOT_SVC_IDS and return the entry at position dev_id
     * (cxi0 → 0, cxi1 → 1, ...).  Returns -1 if the variable is absent
     * or the index is out of range.
     */
    int env_svc_id(unsigned dev_id) const;

    /*
     * Parse SLINGSHOT_VNIS and return the first comma-separated token
     * as a uint16_t.  Returns 0 if the variable is absent.
     */
    uint16_t env_vni() const;

    /*
     * Re-implementation of uct_cxi_find_svc_by_membership()'s selection
     * logic (cxi_md.c) for cross-checking the kernel-side service-
     * membership fallback path independently of the production code under
     * test.  Returns the chosen service ID and fills *vni_out (0 if the
     * service does not restrict VNIs), or -1 if no usable service is
     * found for this process's uid/gid.
     */
    int membership_svc_id(struct cxil_dev *dev, uint16_t *vni_out) const;

    /*
     * Convenience wrapper for uct_md_mem_dereg_v2 so that rcache tests
     * can release references without repeating the params boilerplate.
     */
    ucs_status_t dereg_mem(uct_mem_h memh);
};

#endif /* UCT_CXI_TEST_MD_H */
