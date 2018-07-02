//
// Created by xaqq on 6/4/18.
//

#include "cppkcs11/object.hpp"
#include "cppkcs11.hpp"
#include "cppkcs11/pkcs_c_wrapper.hpp"
#include "pkcsexceptions.hpp"

namespace cppkcs
{

Object::Object(Session &session, CK_OBJECT_HANDLE handle)
    : session_(session)
    , handle_(handle)
{
}

Object::Object(Object &&o) noexcept
    : session_(o.session_)
    , handle_(o.handle_)
{
    o.handle_ = 0;
}

CK_OBJECT_HANDLE Object::native_handle() const
{
    return handle_;
}

std::vector<CK_ATTRIBUTE>
Object::native_get_attributes(std::vector<CK_ATTRIBUTE> attr_templates)
{
    CK_RV ret;
    ret = PKCSAPI::get_attribute_value_(session_.native_handle(), handle_,
                                        attr_templates.data(), attr_templates.size());
    throw_on_error<AttributeException>(ret, "GetAttributeValue");

    // Check size information as this tell us some stuff.
    // See PKCS11 specc for additional information
    for (const auto &attr : attr_templates)
    {
        if (attr.ulValueLen == -1)
        {
            // Attribute is sensitive or unextractable or maybe it doesnt even
            // exists...
            throw AttributeException(ret, "Attribute size is -1");
        }
    }
    return attr_templates;
}
}
