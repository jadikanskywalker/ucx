/**
 * Copyright (c) 2026. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 *
 * Shared fixture base for CXI RMA tests.
 *
 * Provides the two-entity setup (sender at index 0, receiver at index 1),
 * memory registration / deregistration helpers, rkey packing, and a
 * poll-until-flush helper.  Both test_cxi_ep and test_cxi_rma inherit from
 * this class.
 */

#ifndef UCT_TEST_CXI_RMA_H
#define UCT_TEST_CXI_RMA_H

#include <uct/api/uct.h>
#include <common/test.h>
#include <uct/uct_test.h>

#include <string>
#include <vector>


/**
 * test_cxi_rma_base — two-entity fixture for CXI loopback tests.
 *
 * Sender EP (slot 0) is connected to the receiver's iface via
 * connect_to_iface() in each individual test.
 */
class test_cxi_rma_base : public uct_test {
protected:
    void init() override
    {
        uct_test::init();
        m_entities.push_back(uct_test::create_entity(0)); /* sender   */
        m_entities.push_back(uct_test::create_entity(0)); /* receiver */
    }

    entity &sender()   { return m_entities.at(0); }
    entity &receiver() { return m_entities.at(1); }

    /** Register a host buffer on @a ent's MD with RMA access. */
    uct_mem_h reg(entity &ent, void *buf, size_t len)
    {
        uct_md_mem_reg_params_t p;
        p.field_mask = UCT_MD_MEM_REG_FIELD_FLAGS;
        p.flags      = UCT_MD_MEM_ACCESS_RMA;

        uct_mem_h memh = UCT_MEM_HANDLE_NULL;
        EXPECT_UCS_OK(uct_md_mem_reg_v2(ent.md(), buf, len, &p, &memh));
        return memh;
    }

    /** Deregister a previously registered buffer. */
    void dereg(entity &ent, uct_mem_h memh)
    {
        uct_md_mem_dereg_params_t p;
        p.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
        p.memh       = memh;
        EXPECT_UCS_OK(uct_md_mem_dereg_v2(ent.md(), &p));
    }

    /**
     * Pack the rkey for @a memh on @a ent's MD.
     * Returns the packed bytes; caller unpacks with uct_rkey_unpack().
     */
    std::string pack_rkey(entity &ent, uct_mem_h memh,
                          void *buf, size_t len)
    {
        std::string rkey_buf(ent.md_attr().rkey_packed_size, '\0');
        uct_md_mkey_pack_params_t p;
        p.field_mask = 0;
        EXPECT_UCS_OK(uct_md_mkey_pack_v2(ent.md(), memh, buf, len,
                                           &p, &rkey_buf[0]));
        return rkey_buf;
    }

    /**
     * Poll iface_progress + ep_flush on @a ent until all sends posted on
     * @a ep are acknowledged, or a 5-second deadline elapses.
     */
    void flush_ep(entity &ent, uct_ep_h ep)
    {
        ucs_time_t   deadline = ucs_get_time() + ucs_time_from_sec(5.0);
        ucs_status_t status;

        do {
            uct_iface_progress(ent.iface());
            status = uct_ep_flush(ep, 0, NULL);
        } while (status == UCS_INPROGRESS &&
                 ucs_get_time() < deadline);

        ASSERT_EQ(UCS_OK, status) << "ep_flush timed out after 5 s";
    }
};

#endif /* UCT_TEST_CXI_RMA_H */
