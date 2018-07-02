#include "cppkcs11/cppkcs11.hpp"
#include "test_helper.hpp"
#include "gtest/gtest.h"

class TestSession : public TestHelper
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
    auto session = cppkcs::open_session(get_hsm_slot(), 0);
}

// On Atos NetHSM this test is valid, but against SoftHSM
// it is apparently acceptable to logout w/o a previous login.
/*
TEST_F(TestSession, logout_no_login)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(get_hsm_slot(), 0);
    ASSERT_THROW(session.logout(), PKCSException);
}*/

TEST_F(TestSession, login_invalid_password)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(get_hsm_slot(), 0);
    ASSERT_THROW(session.login(SecureString("Toto")), PKCSException);
}

TEST_F(TestSession, login_valid_password)
{
    using namespace cppkcs;
    auto session = cppkcs::open_session(get_hsm_slot(), 0);
    session.login(get_hsm_pin());
    session.logout();
}
