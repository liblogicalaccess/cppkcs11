#include <algorithm>
#include <memory>
#include "gtest/gtest.h"
#include "cppkcs11/cppkcs11.hpp"

/**
 * Problem: Those tests relies on the current setup of test HSM
 * provided by ATOS to us for development.
 *
 * They might need refactoring etc. We will see later.
 */

TEST(General, initialize_finalize)
{
    using namespace cppkcs;

    load_pkcs();
    initialize();
    finalize();
}

TEST(General, double_init)
{
    using namespace cppkcs;

    load_pkcs();
    initialize();
    // Already initialized
    ASSERT_THROW(initialize(), PKCSException);
    finalize();
}

TEST(General, test_secure_array)
{
    // We invoke UB...
    uint8_t *ptr;
    {
        cppkcs::SecureArray<uint8_t, 1024> secure{};
        memset(secure.data(), 1, 1024);
        ptr = secure.data();
        for (int i = 0; i < 1024; ++i)
        {
            ASSERT_EQ(1, ptr[i]);
        }
    }
    // Make sure the memory space was bzero.
    // Its possible this test has issue because it accesses
    // memory it should not.
    for (int i = 0; i < 1024; ++i)
    {
        ASSERT_EQ(0, ptr[i]);
    }
}

// This test invokes UB so it may not be reliable.
/*
TEST(General, test_secure_string)
{
    uint8_t *ptr;
    {
        cppkcs::SecureString secure("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        ptr = secure.data();
        for (int i = 0; i < 6; ++i)
        {
            ASSERT_EQ('A', ptr[i]);
        }
    }
    for (int i = 0; i < 6; ++i)
    {
        ASSERT_EQ(0, ptr[i]);
    }
}
*/

/**
 * Test helper that simply wraps test with call
 * to cppkcs::initialize() and finalize().
 */
class GeneralTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        cppkcs::load_pkcs();
        cppkcs::initialize();
    }

    void TearDown() override
    {
        cppkcs::finalize();
    }
};

TEST_F(GeneralTest, list_slots_noforce_token)
{
    auto slots = cppkcs::get_slot_list(false);

    ASSERT_EQ(8, slots.size());
    // Slot are numbered 1 to 8.
    size_t id = 1;
    for (auto slot_id : slots)
    {
        ASSERT_EQ(id, slot_id);
        ++id;
    }
}

TEST_F(GeneralTest, list_slots_force_token)
{
    auto slots = cppkcs::get_slot_list(true);

    ASSERT_EQ(8, slots.size());
    // Slot are numbered 1 to 8.
    size_t id = 1;
    for (auto slot_id : slots)
    {
        ASSERT_EQ(id, slot_id);
        ++id;
    }
}

TEST_F(GeneralTest, slot_info)
{
    // Start at 1.
    for (size_t i = 1; i < 9; ++i)
    {
        auto info = cppkcs::get_slot_info(i);

        // We need to retrieve the manufacturer.
        auto label          = std::string((const char *)info.manufacturerID);
        auto expected_label = "BULL S.A., Les Clayes, France   \x05";
        ASSERT_EQ(expected_label, label);
    }
}

TEST_F(GeneralTest, token_info)
{
    // Start at 1.
    for (size_t i = 1; i < 9; ++i)
    {
        auto info = cppkcs::get_token_info(i);

        // We need to retrieve the label.
        // Somehow the `label` is not '\0' terminated, so we have to limit to 32, then
        // strip blank.
        auto label = std::string((const char *)info.label, (const char *)info.label + 32);
        label.erase(std::remove_if(label.begin(), label.end(),
                                   [](auto x) { return ::isspace(x); }),
                    label.end());
        auto expected_label = "HSMV" + std::to_string(i);
        ASSERT_EQ(expected_label, label);
    }
}
