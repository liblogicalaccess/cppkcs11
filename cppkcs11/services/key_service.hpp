#pragma once

#include "cppkcs11/cppkcs_fwd.hpp"
#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/services/object_service.hpp"
#include <functional>
#include <vector>

namespace cppkcs
{

/**
 * Service that provides key operations such as:
 *    + Key Generation
 *    + Key Retrieval
 *    + .... ??
 *
 * Similar to ObjectService, the KeyService needs a Session to operate.
 * It is important that the session outlives the service and any object
 * that may be created by the service.
 */
class KeyService
{
  public:
    explicit KeyService(Session &os);

    /**
     * Generate a key.
     *
     * A vector of Attributes can be passed to this function to customize
     * the key.
     */
    Object generate_key(CK_MECHANISM mechanism,
                        const std::vector<std::reference_wrapper<IAttribute>> &attrs);

    /**
     * Generate a key.
     *
     * Attributes can be passed to this function as variadic argument to further
     * customize the key.
     */
    template <typename... Attributes>
    Object generate_key(CK_MECHANISM mechanism, Attributes &&... attrs)
    {
        return generate_key(mechanism, {attrs...});
    }

    /**
     * Generate an AES 128 bits key.
     *
     * Pass the attribute<CKA_TOKEN>(true) to make the generated key
     * persistent.
     */
    template <typename... Attributes>
    Object generate_aes_128_key(Attributes &&... attrs)
    {
        CK_MECHANISM mechanism;
        mechanism.mechanism      = CKM_AES_KEY_GEN;
        mechanism.pParameter     = nullptr;
        mechanism.ulParameterLen = 0;

        return generate_key(mechanism, make_attribute<CKA_VALUE_LEN>(16), attrs...);
    }

    /**
     * Helper function to import an AES key.
     *
     * Additional attributes can be passed to the function, as usual.
     * The key_value parameters is automatically converted to an attribute
     * and used to create the key.
     */
    template <typename... Attributes>
    Object import_aes_key(const SecureString &key_value, Attributes &&... attrs)
    {
        ObjectService os(session_);
        return os.create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                                make_attribute<CKA_KEY_TYPE>(KeyType::AES),
                                make_attribute<CKA_VALUE>(key_value), attrs...);
    }

    // Derive_key not implemented due to HSM issues.
    /*
        Object derive_key(const Object &base_key,
                          const std::vector<std::reference_wrapper<IAttribute>>
       &attrs);

        template <typename... Attributes>
        Object derive_key(const Object &base_key, Attributes &&... attrs)
        {
            return derive_key(base_key, {attrs...});
        }*/

  private:
    Session &session_;
};
}
