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
};

#endif /* UCT_CXI_TEST_MD_H */
