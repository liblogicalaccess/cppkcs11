#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/services/key_service.hpp"
#include "cppkcs11/services/object_service.hpp"
#include "test_helper.hpp"
#include "gtest/gtest.h"
#include <algorithm>
#include <cppkcs11/services/crypto_service.hpp>

class CryptoServiceTest : public TestHelper
{
  protected:
    void SetUp() override
    {
        cppkcs::load_pkcs();
        cppkcs::initialize();

        auto session = cppkcs::open_session(get_hsm_slot(), CKS_RW_USER_FUNCTIONS);
        session_     = std::make_unique<cppkcs::Session>(std::move(session));
        session_->login(get_hsm_pin());

        service_     = std::make_unique<cppkcs::CryptoService>(*session_);
        key_service_ = std::make_unique<cppkcs::KeyService>(*session_);

        // Clear everything before tests
        cppkcs::ObjectService(*session_).destroy_all();
    }

    void TearDown() override
    {
        // We need to null our pointers, otherwise we will finalize() before
        // objects' destruction.

        if (session_)
            session_->logout();
        service_     = nullptr;
        key_service_ = nullptr;
        session_     = nullptr;
        cppkcs::finalize();
    }

    std::unique_ptr<cppkcs::Session> session_;
    std::unique_ptr<cppkcs::KeyService> key_service_;
    std::unique_ptr<cppkcs::CryptoService> service_;
};

TEST_F(CryptoServiceTest, test_encrypt_decrypt)
{
    using namespace cppkcs;

    auto key = key_service_->generate_aes_128_key();

    auto payload = SecureString("Hello World 1234");
    auto iv      = std::vector<uint8_t>({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    auto encrypted = service_->aes_encrypt(payload, iv, key);
    auto clear     = service_->aes_decrypt(encrypted, iv, key);

    ASSERT_EQ(payload, clear);
}

TEST_F(CryptoServiceTest, test_encrypt_decrypt_2)
{
    using namespace cppkcs;

    auto key = key_service_->generate_aes_128_key();

    auto payload = SecureString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB");
    auto iv      = std::vector<uint8_t>({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    auto encrypted = service_->aes_encrypt(payload, iv, key);
    auto clear     = service_->aes_decrypt(encrypted, iv, key);

    ASSERT_EQ(payload, clear);
}

TEST_F(CryptoServiceTest, test_encrypt_decrypt_fail_1)
{
    using namespace cppkcs;

    auto key = key_service_->generate_aes_128_key();

    auto payload = SecureString("Payload Is Not 16 bytes blocks");
    auto iv      = std::vector<uint8_t>({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    ASSERT_THROW(service_->aes_encrypt(payload, iv, key), PKCSException);
}
