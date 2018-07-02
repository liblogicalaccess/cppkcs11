#include "cppkcs11/services/object_service.hpp"
#include "cppkcs11/cppkcs11.hpp"
#include <cppkcs11/pkcs_c_wrapper.hpp>
#include <cstddef>

namespace cppkcs
{

ObjectService::ObjectService(Session &session)
    : session_(session)
{
}

void ObjectService::destroy_all()
{
    for (auto &object : find_objects())
    {
        destroy(std::move(object));
    }
}

std::vector<Object>
ObjectService::find_objects(const std::vector<std::reference_wrapper<IAttribute>> &attrs)
{
    static constexpr const size_t NUMBER_ITEMS_PER_ITERATIONS = 32;
    CK_RV ret;
    std::vector<Object> objects;

    auto native_attributes = as_native_attributes_v(attrs);
    ret = PKCSAPI::find_objects_init_(session_.native_handle(), native_attributes.data(),
                                      native_attributes.size());
    throw_on_error<PKCSException>(ret, "FindObjectsInit");

    // We fetch up to NUMBER_ITEMS_PER_ITERATIONS objects at once.
    CK_ULONG received_object_counts;
    do
    {
        std::array<CK_OBJECT_HANDLE, NUMBER_ITEMS_PER_ITERATIONS> object_handle{};
        ret = PKCSAPI::find_objects_(session_.native_handle(), object_handle.data(),
                                     object_handle.size(), &received_object_counts);
        throw_on_error<PKCSException>(ret, "FindObjects");
        for (size_t i = 0; i < received_object_counts; ++i)
            objects.emplace_back(session_, object_handle[i]);
    } while (received_object_counts == NUMBER_ITEMS_PER_ITERATIONS);

    // Finally we close the search.
    ret = PKCSAPI::find_objects_final_(session_.native_handle());
    throw_on_error<PKCSException>(ret, "FindObjectsFinal");
    return objects;
}

void ObjectService::destroy(Object &&obj)
{
    CK_RV ret;
    ret = PKCSAPI::destroy_object_(session_.native_handle(), obj.native_handle());
    throw_on_error<AttributeException>(ret, "DestroyObject");
}

Object
ObjectService::create_object(const std::vector<std::reference_wrapper<IAttribute>> &attrs)
{
    CK_RV ret;
    CK_OBJECT_HANDLE object_handle;

    auto native_attrs = as_native_attributes_v(attrs);
    std::cout << "Hello" << std::endl;

    ret = PKCSAPI::create_object_(session_.native_handle(), native_attrs.data(),
                                  native_attrs.size(), &object_handle);
    std::cout << "DEAD ??" << std::endl;
    throw_on_error<AttributeException>(ret, "CreateObject");
    std::cout << "???" << std::endl;
    return Object(session_, object_handle);
}
}
