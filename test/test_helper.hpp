#pragma once

#include "gtest/gtest.h"

/*
#define HSM_USER_PIN cppkcs::SecureString("titi")
#define NETHSM_SLOT 680266410
*/

//#define HSM_USER_PIN cppkcs::SecureString("qqqq")
//#define NETHSM_SLOT 1981080426

class TestHelper : public ::testing::Test
{
  protected:
    cppkcs::SecureString get_hsm_pin()
    {
        const char *pin = getenv("CPPKCS11_UNITTEST_PIN");
        if (pin == nullptr)
        {
            std::cerr << "No PIN configured in CPPKCS11_UNITTEST_PIN" << std::endl;
            exit(-1);
        }
        return cppkcs::SecureString(pin);
    }

    const char *get_hsm_pin_cstr()
    {
        const char *pin = getenv("CPPKCS11_UNITTEST_PIN");
        if (pin == nullptr)
        {
            std::cerr << "No PIN configured in CPPKCS11_UNITTEST_PIN" << std::endl;
            exit(-1);
        }
        return pin;
    }

    size_t get_hsm_slot()
    {
        const char *slot = getenv("CPPKCS11_UNITTEST_TOKEN_SLOT");
        if (slot == nullptr)
        {
            std::cerr << "No token slot configured in CPPKCS11_UNITTEST_TOKEN_SLOT"
                      << std::endl;
            exit(-1);
        }
        return std::stoull(slot);
    }
};
