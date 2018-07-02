#include "cppkcs11/services/key_service.hpp"
#include "object_service.hpp"
#include <cppkcs11/attribute.hpp>
#include <cppkcs11/cppkcs11.hpp>
#include <cppkcs11/pkcs_c_wrapper.hpp>
#include <cppkcs11/pkcsexceptions.hpp>

namespace cppkcs
{

KeyService::KeyService(Session &session)
    : session_(session)
{
}

Object
KeyService::generate_key(CK_MECHANISM mechanism,
                         const std::vector<std::reference_wrapper<IAttribute>> &attrs)
{
    CK_RV ret;
    CK_OBJECT_HANDLE key_handle;

    auto native_attributes = as_native_attributes_v(attrs);

    ret = PKCSAPI::generate_key_(session_.native_handle(), &mechanism,
                                 native_attributes.data(), native_attributes.size(),
                                 &key_handle);
    throw_on_error<PKCSException>(ret, "GenerateKey");
    return Object(session_, key_handle);
}

/*Object
KeyService::derive_key(const Object &base_key,
                       const std::vector<std::reference_wrapper<IAttribute>>
&attrs)
{
    CK_MECHANISM mechanism;
    ByteVector iv              = ByteVector(16);
    ByteVector derivation_data = ByteVector(16, 2);

    CK_AES_CBC_ENCRYPT_DATA_PARAMS p;
    memcpy(p.iv, iv.data(), 16);
    p.length = derivation_data.size();
    p.pData  = derivation_data.data();

    ByteVector derivation_parameter;
    derivation_parameter.insert(derivation_parameter.begin(), iv.begin(),
iv.end());
    derivation_parameter.insert(derivation_parameter.begin(),
derivation_data.begin(),
                                derivation_data.end());

    mechanism.mechanism      = CKM_AES_CBC_ENCRYPT_DATA;
    mechanism.ulParameterLen = sizeof(p);
    mechanism.pParameter     = &p;
    CK_RV ret;
    CK_OBJECT_HANDLE key_handle;

    auto native_attributes = as_native_attributes_v(attrs);
    ret                    = PKCSAPI::derive_key_(session_.native_handle(),
&mechanism,
                               base_key.native_handle(),
native_attributes.data(),
                               native_attributes.size(), &key_handle);
    throw_on_error<PKCSException>(ret, "DeriveKey");
    return Object(session_, key_handle);
}*/
}
