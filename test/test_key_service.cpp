#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/services/key_service.hpp"
#include "cppkcs11/services/object_service.hpp"
#include "test_helper.hpp"
#include "gtest/gtest.h"
#include <algorithm>

/**
 * Tests in this file kinda assume that other call
 * work correctly. Most feature relies on each other
 * to perform testing...
 */

class KeyServiceTest : public TestHelper
{
  protected:
    void SetUp() override
    {
        cppkcs::load_pkcs();
        cppkcs::initialize();
        auto session = cppkcs::open_session(get_hsm_slot(), CKS_RW_USER_FUNCTIONS);
        session_     = std::make_unique<cppkcs::Session>(std::move(session));
        session_->login(get_hsm_pin());

        service_ = std::make_unique<cppkcs::KeyService>(*session_);

        // Clear everything before tests
        cppkcs::ObjectService(*session_).destroy_all();
    }

    void TearDown() override
    {
        // We need to null our pointers, otherwise we will finalize() before
        // objects' destruction.

        if (session_)
            session_->logout();
        service_ = nullptr;
        session_ = nullptr;
        cppkcs::finalize();
    }

    std::unique_ptr<cppkcs::Session> session_;
    std::unique_ptr<cppkcs::KeyService> service_;
};

TEST_F(KeyServiceTest, test_generate_key_1)
{
    using namespace cppkcs;
    auto key = service_->generate_aes_128_key();

    ASSERT_EQ(16, key.get_attribute<CKA_VALUE_LEN>());
}

TEST_F(KeyServiceTest, test_generate_key_2)
{
    using namespace cppkcs;
    auto key = service_->generate_aes_128_key(make_attribute<CKA_LABEL>("MyAesKey"));

    ASSERT_EQ(16, key.get_attribute<CKA_VALUE_LEN>());
    ASSERT_EQ("MyAesKey", key.get_attribute<CKA_LABEL>().data_);
    ASSERT_THROW(key.get_attribute<CKA_VALUE>(), AttributeException);
}

TEST_F(KeyServiceTest, test_get_key_value_ok)
{
    using namespace cppkcs;

    // Extractable true, sensitive false --> we can retrieve value.
    auto key = service_->generate_aes_128_key(make_attribute<CKA_LABEL>("MyAesKey"),
                                              make_attribute<CKA_EXTRACTABLE>(true),
                                              make_attribute<CKA_SENSITIVE>(false));

    ASSERT_EQ(16, key.get_attribute<CKA_VALUE_LEN>());
    ASSERT_EQ("MyAesKey", key.get_attribute<CKA_LABEL>().data_);

    // We should be able to retrieve because the key is EXTRACTABLE
    ASSERT_EQ(16, key.get_attribute<CKA_VALUE>().data_.size());
}

TEST_F(KeyServiceTest, test_get_key_value_ko)
{
    using namespace cppkcs;

    // If the key is either not extractable or sensitive, we cannot retrieve
    // value.
    auto key = service_->generate_aes_128_key(make_attribute<CKA_LABEL>("MyAesKey"),
                                              make_attribute<CKA_EXTRACTABLE>(false),
                                              make_attribute<CKA_SENSITIVE>(false));
    ASSERT_THROW(key.get_attribute<CKA_VALUE>(), AttributeException);

    // If the key is either not extractable or sensitive, we cannot retrieve
    // value.
    auto key2 = service_->generate_aes_128_key(make_attribute<CKA_LABEL>("MyAesKey2"),
                                               make_attribute<CKA_EXTRACTABLE>(true),
                                               make_attribute<CKA_SENSITIVE>(true));
    ASSERT_THROW(key2.get_attribute<CKA_VALUE>(), AttributeException);
}

TEST_F(KeyServiceTest, test_generate_key_is_local)
{
    using namespace cppkcs;

    auto key = service_->generate_aes_128_key(make_attribute<CKA_LABEL>("MyAesKey"));
    ASSERT_EQ(key.get_attribute<CKA_LOCAL>(), true);
}

TEST_F(KeyServiceTest, test_imported_key_is_not_local)
{
    using namespace cppkcs;

    SecureString key_value({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
    auto key = service_->import_aes_key(key_value, make_attribute<CKA_LABEL>("MyAesKey"));

    // This key is non local
    ASSERT_EQ(key.get_attribute<CKA_LOCAL>(), false);
    ASSERT_THROW(key.get_attribute<CKA_VALUE>(), AttributeException);
}

TEST_F(KeyServiceTest, test_import_export)
{
    using namespace cppkcs;

    SecureString key_value({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
    auto key = service_->import_aes_key(key_value, make_attribute<CKA_LABEL>("MyAesKey"),
                                        make_attribute<CKA_EXTRACTABLE>(true),
                                        make_attribute<CKA_SENSITIVE>(false));

    // Make sure we retrieve our initial key value.
    auto key_value_export = key.get_attribute<CKA_VALUE>().data_;
    ASSERT_EQ(key_value, key_value_export);
}

TEST_F(KeyServiceTest, test_derive_key)
{
    // This crash the Atos HSM....
    /*    using namespace cppkcs;

        SecureString key_value({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
       15});
        auto key = service_->import_aes_key(key_value,
       make_attribute<CKA_LABEL>("MyAesKey"),
                                            make_attribute<CKA_DERIVE>(true),
                                            make_attribute<CKA_EXTRACTABLE>(true),
                                            make_attribute<CKA_SENSITIVE>(false));

        auto derived_key = service_->derive_key(
            key, make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
            make_attribute<CKA_ENCRYPT>(true), make_attribute<CKA_DECRYPT>(true),
            make_attribute<CKA_EXTRACTABLE>(true),
       make_attribute<CKA_SENSITIVE>(false),
            make_attribute<CKA_KEY_TYPE>(KeyType::AES),
       make_attribute<CKA_VALUE_LEN>(16));

        auto value = derived_key.get_attribute<CKA_VALUE>().data_;
        std::cout << std::string((const char *)value.data(), value.size()) <<
       std::endl;*/
}
