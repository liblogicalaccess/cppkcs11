#pragma once

#include <string>
#include "cppkcs11/cppkcs_fwd.hpp"

namespace cppkcs
{

/**
 * Provide an easy to use API to perform cryptographic operation
 * using PKCS11 API.
 */
class CryptoService
{
  public:
    explicit CryptoService(Session &session);

    /**
     * Perform AES CBC encryption on the `data`, using `iv` as an
     * initialization vector and `key` as the PKCS key object.
     */
    std::vector<uint8_t> aes_encrypt(const SecureString &data,
                                     const std::vector<uint8_t> &iv, const Object &key);

    /**
     * Perform AES CBC decryption on the `data`, using `iv` as
     * the initialization vector and key as the PKCS key object.
     */
    SecureString aes_decrypt(const std::vector<uint8_t> &data,
                             const std::vector<uint8_t> &iv, const Object &key);

  private:
    Session &session_;
};
}
