#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/services/object_service.hpp"
#include "gtest/gtest.h"
#include "cppkcs11/c_api.h"
#include "test_helper.hpp"

class CAPITest : public TestHelper
{
    void SetUp() override
    {
        cppkcs_load_pkcs(nullptr);
        cppkcs_initialize();

        auto session = cppkcs::open_session(get_hsm_slot(), CKS_RW_USER_FUNCTIONS);
        session.login(get_hsm_pin());
        cppkcs::ObjectService(session).destroy_all();
    }

    void TearDown() override
    {
        cppkcs_finalize();
    }
};

TEST_F(CAPITest, generate_key)
{
    uint8_t buffer[16] = {};

    ASSERT_EQ(0, cppkcs_has_object_with_label((const char *)get_hsm_pin().data(),
                                              get_hsm_slot(), "MY_KEY_LABEL"));
    ASSERT_EQ(0, cppkcs_generate_aes128((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));
    size_t value = 0;
    for (unsigned char i : buffer)
        value += i;
    // Unless we are very (un)lucky and generate a full zero key...
    // ... the following assertion will hold
    ASSERT_NE(0, value);

    // Now we have one...
    ASSERT_EQ(1, cppkcs_has_object_with_label((const char *)get_hsm_pin().data(),
                                              get_hsm_slot(), "MY_KEY_LABEL"));

    // Try to dump it.
    uint8_t dump_buffer[16];
    ASSERT_EQ(0, cppkcs_dump_key_value((const char *)get_hsm_pin().data(), get_hsm_slot(),
                                       "MY_KEY_LABEL", dump_buffer));

    // Make sure key are the same.
    for (int i = 0; i < 16; ++i)
        ASSERT_EQ(buffer[i], dump_buffer[i]);
}

TEST_F(CAPITest, dump_non_existent_fails)
{
    uint8_t buffer[16] = {};
    ASSERT_EQ(-1, cppkcs_dump_key_value((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));
}

TEST_F(CAPITest, generate_duplicate_label)
{
    uint8_t buffer[16] = {};

    ASSERT_EQ(0, cppkcs_generate_aes128((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));
    ASSERT_EQ(0, cppkcs_generate_aes128((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));
    ASSERT_EQ(0, cppkcs_generate_aes128((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));
    ASSERT_EQ(0, cppkcs_generate_aes128((const char *)get_hsm_pin().data(),
                                        get_hsm_slot(), "MY_KEY_LABEL", buffer));

    ASSERT_EQ(4, cppkcs_has_object_with_label((const char *)get_hsm_pin().data(),
                                              get_hsm_slot(), "MY_KEY_LABEL"));
}
