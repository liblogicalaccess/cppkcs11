#include "cppkcs11/attribute.hpp"

namespace cppkcs
{
std::vector<CK_ATTRIBUTE>
as_native_attributes_v(const std::vector<std::reference_wrapper<IAttribute>> &attrs)
{
    std::vector<CK_ATTRIBUTE> native_attrs;
    for (auto &attr : attrs)
    {
        native_attrs.emplace_back(attr.get().as_native_attribute());
    }
    return native_attrs;
}
}
