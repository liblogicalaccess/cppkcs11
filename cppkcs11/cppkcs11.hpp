#pragma once

#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/object.hpp"
#include "cppkcs11/pkcsexceptions.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/session.hpp"
#include "cppkcs11/cppkcs11_export.h"
#include <map>
#include <vector>

/**
 * C++ wrapping of some PKCS functions.
 *
 * All methods from all objects, aswell as free function in the cppkcs
 * namespace can throw exception when an error occur.
 * Most likely, an exception derived from PKCSException will be thrown
 * when the underlying PKCS library returns an error.
 */
namespace cppkcs
{

// Map error code value to a more user friendly string.
// This map is generated with the pkcs_error_code_to_string.py script.
extern std::map<size_t, std::string> pkcs_error_code_to_string;

/**
 * Load the underlying PKCS library. This is required for cppkcs
 * to work.
 *
 * This must be called once BEFORE calling initialize()
 */
void CPPKCS11_EXPORT load_pkcs(const std::string &pkcs_shared_object_path);

/**
 * Load the underlying PKCS library. This uses the CPPKCS11_UNDERLYING_LIBRARY
 * environment variable for the path to the PKCS shared object.
 */
void CPPKCS11_EXPORT load_pkcs();

/**
 * Wraps C_Initialize()
 */
void CPPKCS11_EXPORT initialize();

void CPPKCS11_EXPORT finalize();

std::vector<CK_SLOT_ID> get_slot_list(bool token_present);

CK_SLOT_INFO get_slot_info(CK_SLOT_ID slot_id);

CK_TOKEN_INFO get_token_info(CK_SLOT_ID slot_id);

/**
 * Open a PKCS session.
 *
 * The CKF_SERIAL_SESSION flags is added to the flags provided
 * by the caller.
 */
Session CPPKCS11_EXPORT open_session(CK_SLOT_ID slot_id, CK_FLAGS flags);

/**
 * Close a session with a given handle.
 *
 * Note that this function SHOULD NOT be called manually.
 * It will be called automatically when a Session object goes
 * out of scope.
 */
void CPPKCS11_EXPORT close_session(CK_SESSION_HANDLE session_handle);

/**
 * Ensure that there is no error (based on the CK_RV errcode param).
 *
 * This is used to easily check native PKCS call return value.
 *
 * Is there is, we throw the `T` exception.
 */
template <typename ExceptionT, typename... Args>
void throw_on_error(CK_RV errcode, Args &&... exception_ctor_args)
{
    static_assert(std::is_base_of<PKCSException, ExceptionT>::value,
                  "Custom exception must derive from PKCSException");

    if (errcode != CKR_OK)
    {
        throw ExceptionT(errcode, exception_ctor_args...);
    }
};
}
