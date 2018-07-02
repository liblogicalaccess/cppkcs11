//
// Created by xaqq on 6/4/18.
//

#include <cassert>
#include "cppkcs11/session.hpp"
#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/object.hpp"
#include "cppkcs11/pkcsexceptions.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/pkcs_c_wrapper.hpp"

namespace cppkcs
{

Session::Session(CK_SESSION_HANDLE native_handle, CK_SLOT_ID slot_id)
    : handle_(native_handle)
    , slot_id_(slot_id)
{
}

Session::~Session()
{
    if (handle_ != 0)
    {
        try
        {
            close_session(handle_);
        }
        catch (const PKCSException &e)
        {
            std::cerr << "Failed to close_session() from Session destructor: " << e.what()
                      << std::endl;
        }
    }
}

Session::Session(Session &&o) noexcept
{
    slot_id_ = o.slot_id_;
    handle_  = o.handle_;

    o.handle_ = 0;
}

CK_SESSION_HANDLE Session::native_handle() const
{
    return handle_;
}

void Session::login(const SecureString &password)
{
    CK_RV ret;
    ret = PKCSAPI::login_(handle_, CKU_USER, (CK_UTF8CHAR_PTR)password.data(),
                          password.size());
    throw_on_error<PKCSException>(ret, "Login");
}

void Session::logout()
{
    CK_RV ret;
    ret = PKCSAPI::logout_(handle_);
    throw_on_error<PKCSException>(ret, "Logout");
}
}
