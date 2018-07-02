#include "cppkcs11/services/crypto_service.hpp"
#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/object.hpp"
#include "cppkcs11/pkcsexceptions.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/session.hpp"
#include <cassert>
#include <cppkcs11/pkcs_c_wrapper.hpp>

namespace cppkcs
{
CryptoService::CryptoService(Session &session)
    : session_(session)
{
}

std::vector<uint8_t> CryptoService::aes_encrypt(const SecureString &data,
                                                const std::vector<uint8_t> &iv,
                                                const Object &key)
{
    CK_RV ret;

    CK_MECHANISM mech{};
    mech.mechanism  = CKM_AES_CBC;
    mech.pParameter = const_cast<CK_VOID_PTR>(reinterpret_cast<const void *>(iv.data()));
    mech.ulParameterLen = iv.size();

    ret = PKCSAPI::encrypt_init_(session_.native_handle(), &mech, key.native_handle());
    throw_on_error<PKCSException>(ret, "Encrypt (AES)");

    CK_ULONG encrypted_data_length = data.size();
    std::vector<uint8_t> encrypted(data.size());
    // We have to remove constness due to PKCS API. In practice, because
    // data.data() is
    // the input it should be read-only...
    ret =
        PKCSAPI::encrypt_(session_.native_handle(), const_cast<CK_BYTE_PTR>(data.data()),
                          data.size(), encrypted.data(), &encrypted_data_length);
    throw_on_error<PKCSException>(ret, "Encrypt (AES)");
    return encrypted;
}

SecureString CryptoService::aes_decrypt(const std::vector<uint8_t> &data,
                                        const std::vector<uint8_t> &iv, const Object &key)
{
    CK_RV ret;

    CK_MECHANISM mech{};
    mech.mechanism  = CKM_AES_CBC;
    mech.pParameter = const_cast<CK_VOID_PTR>(reinterpret_cast<const void *>(iv.data()));
    mech.ulParameterLen = iv.size();

    ret = PKCSAPI::decrypt_init_(session_.native_handle(), &mech, key.native_handle());
    throw_on_error<PKCSException>(ret, "Decrypt (AES)");

    CK_ULONG decrypted_data_length = data.size();
    // Simply initialize the output with the input in oder for "decrypted"
    // to have the correct size directly
    SecureString decrypted(std::string(data.begin(), data.end()));
    ret =
        PKCSAPI::decrypt_(session_.native_handle(), const_cast<CK_BYTE_PTR>(data.data()),
                          data.size(), decrypted.data(), &decrypted_data_length);
    throw_on_error<PKCSException>(ret, "Decrypt (AES)");
    return decrypted;
}
}
