#pragma once

#include <string>
#include "cppkcs11/native_pkcs.hpp"

namespace cppkcs
{
/**
 * Dynamic library wrapper around (part of) PKCS11 C API.
 *
 * The cppkcs C++ library does not call PKCS11 function
 * directly. Instead it dlopen() a dynamic shared object
 * and load symbol from there.
 * Because of that we have no link time dependencies
 * against a PKCS implementation.
 *
 * The init_function_pointers() is responsible for loading
 * symbol from the underlying PKCS library.
 *
 * The PKCSAPI class is for internal usage by cppkcs.
 */
class PKCSAPI
{
  public:
    static void init_function_pointers(const std::string &pkcs_shared_object_path);

    static decltype(&::C_GenerateKey) generate_key_;
    static decltype(&::C_CloseSession) close_session_;
    static decltype(&::C_FindObjectsInit) find_objects_init_;
    static decltype(&::C_Logout) logout_;
    static decltype(&::C_OpenSession) open_session_;
    static decltype(&::C_EncryptInit) encrypt_init_;
    static decltype(&::C_FindObjectsFinal) find_objects_final_;
    static decltype(&::C_DecryptInit) decrypt_init_;
    static decltype(&::C_GetSlotList) get_slot_list_;
    static decltype(&::C_Login) login_;
    static decltype(&::C_GetSlotInfo) get_slot_info_;
    static decltype(&::C_GetAttributeValue) get_attribute_value_;
    static decltype(&::C_Encrypt) encrypt_;
    static decltype(&::C_Decrypt) decrypt_;
    static decltype(&::C_Initialize) initialize_;
    static decltype(&::C_Finalize) finalize_;
    static decltype(&::C_DeriveKey) derive_key_;
    static decltype(&::C_FindObjects) find_objects_;
    static decltype(&::C_CreateObject) create_object_;
    static decltype(&::C_GetTokenInfo) get_token_info_;
    static decltype(&::C_DestroyObject) destroy_object_;
};
}
