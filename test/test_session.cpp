#include "gtest/gtest.h"
#include "cppkcs11/cppkcs11.hpp"
#include "test_helper.hpp"

class TestSession : public ::testing::Test
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

TEST_F(TestSession, create)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(NETHSM_SLOT, 0);
}

TEST_F(TestSession, logout_no_login)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(NETHSM_SLOT, 0);
    ASSERT_THROW(session.logout(), PKCSException);
}

TEST_F(TestSession, login_invalid_password)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(NETHSM_SLOT, 0);
    ASSERT_THROW(session.login(SecureString("Toto")), PKCSException);
}

TEST_F(TestSession, login_valid_password)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(NETHSM_SLOT, 0);
    session.login(HSM_USER_PIN);
    session.logout();
}
