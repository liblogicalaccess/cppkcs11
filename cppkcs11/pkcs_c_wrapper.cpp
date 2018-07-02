#include <string>
#include <stdexcept>
#include <iostream>
#include "cppkcs11/pkcs_c_wrapper.hpp"

#ifdef __linux__
#include <dlfcn.h>
#else
#include <Windows.h>
#endif

namespace cppkcs
{

decltype(&::C_GenerateKey) PKCSAPI::generate_key_;
decltype(&::C_CloseSession) PKCSAPI::close_session_;
decltype(&::C_FindObjectsInit) PKCSAPI::find_objects_init_;
decltype(&::C_Logout) PKCSAPI::logout_;
decltype(&::C_OpenSession) PKCSAPI::open_session_;
decltype(&::C_EncryptInit) PKCSAPI::encrypt_init_;
decltype(&::C_FindObjectsFinal) PKCSAPI::find_objects_final_;
decltype(&::C_DecryptInit) PKCSAPI::decrypt_init_;
decltype(&::C_GetSlotList) PKCSAPI::get_slot_list_;
decltype(&::C_Login) PKCSAPI::login_;
decltype(&::C_GetSlotInfo) PKCSAPI::get_slot_info_;
decltype(&::C_GetAttributeValue) PKCSAPI::get_attribute_value_;
decltype(&::C_Encrypt) PKCSAPI::encrypt_;
decltype(&::C_Decrypt) PKCSAPI::decrypt_;
decltype(&::C_Initialize) PKCSAPI::initialize_;
decltype(&::C_Finalize) PKCSAPI::finalize_;
decltype(&::C_DeriveKey) PKCSAPI::derive_key_;
decltype(&::C_FindObjects) PKCSAPI::find_objects_;
decltype(&::C_CreateObject) PKCSAPI::create_object_;
decltype(&::C_GetTokenInfo) PKCSAPI::get_token_info_;
decltype(&::C_DestroyObject) PKCSAPI::destroy_object_;

class PKCSAPI_Impl : public PKCSAPI
{
  public:
    explicit PKCSAPI_Impl(const std::string &so_path)
        : shared_object_path_(so_path)
    {
        load_symbols();
    }

  private:
    template <typename FunctionT, typename SharedObjectHandleT>
    void load_single_symbol(FunctionT &ptr, SharedObjectHandleT shared_object_handle,
                            const char *symbol_name)
    {
#ifdef __linux__
        dlerror();
        void *sym         = dlsym(shared_object_handle, symbol_name);
        const char *error = dlerror();
        if (error)
        {
            throw std::runtime_error("dlsym failed: " + std::string(error));
        }
        ptr = reinterpret_cast<typename std::remove_reference<decltype(ptr)>::type>(sym);
#else
        // segfault without remove remove_reference when null pointer on MSVC.
        // incorrect code / UB or compiler bug ?
        ptr = reinterpret_cast<std::remove_reference<decltype(ptr)>::type>(
            GetProcAddress(shared_object_handle, symbol_name));
        if (ptr == nullptr)
        {
            auto ec = GetLastError();
            throw std::runtime_error("GetProcAddress failed: " + std::to_string(ec));
        }
#endif
    }

    void load_symbols()
    {
#ifdef __linux__
        void *handle = dlopen(shared_object_path_.c_str(), RTLD_NOW);
        if (handle == nullptr)
        {
            const char *error = dlerror();
            throw std::runtime_error("dlopen failed: " + std::string(error));
        }
#else
        HMODULE handle = LoadLibrary(shared_object_path_.c_str());
        if (handle == nullptr)
        {
            auto ec = GetLastError();
            throw std::runtime_error("GetModuleHandle failed: " + std::to_string(ec));
        }
#endif
        load_single_symbol(generate_key_, handle, "C_GenerateKey");
        load_single_symbol(close_session_, handle, "C_CloseSession");
        load_single_symbol(find_objects_init_, handle, "C_FindObjectsInit");
        load_single_symbol(logout_, handle, "C_Logout");
        load_single_symbol(open_session_, handle, "C_OpenSession");
        load_single_symbol(encrypt_init_, handle, "C_EncryptInit");
        load_single_symbol(find_objects_final_, handle, "C_FindObjectsFinal");
        load_single_symbol(decrypt_init_, handle, "C_DecryptInit");
        load_single_symbol(get_slot_list_, handle, "C_GetSlotList");
        load_single_symbol(login_, handle, "C_Login");
        load_single_symbol(get_slot_info_, handle, "C_GetSlotInfo");
        load_single_symbol(get_attribute_value_, handle, "C_GetAttributeValue");
        load_single_symbol(encrypt_, handle, "C_Encrypt");
        load_single_symbol(decrypt_, handle, "C_Decrypt");
        load_single_symbol(initialize_, handle, "C_Initialize");
        load_single_symbol(finalize_, handle, "C_Finalize");
        load_single_symbol(derive_key_, handle, "C_DeriveKey");
        load_single_symbol(find_objects_, handle, "C_FindObjects");
        load_single_symbol(create_object_, handle, "C_CreateObject");
        load_single_symbol(get_token_info_, handle, "C_GetTokenInfo");
        load_single_symbol(destroy_object_, handle, "C_DestroyObject");
    }

    std::string shared_object_path_;
};


void PKCSAPI::init_function_pointers(const std::string &pkcs_shared_object_path)
{
    // Function pointers are static, so instanciating PKCSAPI_Impl
    // once is enough.
    PKCSAPI_Impl impl{pkcs_shared_object_path};
}
}
