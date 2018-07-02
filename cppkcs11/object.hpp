#pragma once

#include "cppkcs11/attribute.hpp"
#include "cppkcs11/cppkcs_fwd.hpp"
#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/secure_memory/secure_array.hpp"
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <tuple>
#include <vector>

namespace cppkcs
{
/**
 * Wraps a PKCS Object.
 *
 * A PKCS object is somewhat tied to a Session because a
 * Session is needed in order to retrieve the object attributes.
 *
 * Therefore it is the user responsibility that an Object instance
 * does not outlive its owner Session instance.
 */
class Object
{
  public:
    explicit Object(Session &session, CK_OBJECT_HANDLE handle);

    Object(const Object &) = delete;
    Object &operator=(const Object &) = delete;

    Object(Object &&) noexcept;

    /**
     * Retrieve the PKCS native handle from the object.
     */
    CK_OBJECT_HANDLE native_handle() const;

    /**
     * Retrieve a single attribute.
     */
    template <CK_ATTRIBUTE_TYPE PKCSAttributeType>
    Attribute<PKCSAttributeType> get_attribute()
    {
        return std::get<0>(get_attributes<PKCSAttributeType>());
    }

    /**
     * Fetch multiples attributes from the PKCS object.
     *
     * @note: Steps:
     *   + We create a buffer (std::array) for each attributes.
     *   + Each CK_ATTRIBUTE set its data-pointer to one of the std::array buffer.
     *   + Our Attribute<T> are configured using data stored in std::array buffer.
     *
     * @tparam PKCSAttributeType PKCS attributes to fetch.
     */
    template <CK_ATTRIBUTE_TYPE... PKCSAttributeType>
    std::tuple<Attribute<PKCSAttributeType>...> get_attributes()
    {
        // Buffer each attributes. The buffers all have the size of the biggest
        // attributes.
        SecureArray<uint8_t, compute_buffer_size<PKCSAttributeType...>()>
            buffers[sizeof...(PKCSAttributeType)] = {};

        // Create a vector of CK_ATTRIBUTE for each attribute we plan to fetch...
        std::vector<CK_ATTRIBUTE> attributes_to_fetch{
            make_attr_template<PKCSAttributeType>()...};
        // ... Now we edit those CK_ATTRIBUTE to configure their underlying buffer.
        for (size_t i = 0; i < attributes_to_fetch.size(); ++i)
        {
            attributes_to_fetch[i].pValue = buffers[i].data();
            // Just to be extra safe
            // MSCV needs help so we cast to size_t.
            attributes_to_fetch[i].ulValueLen =
                std::min(buffers[i].size(), (size_t)attributes_to_fetch[i].ulValueLen);
        }

        attributes_to_fetch = native_get_attributes(attributes_to_fetch);
        auto attrs          = std::make_tuple(Attribute<PKCSAttributeType>()...);

        // A sequence to help iterate over the tuple.
        std::make_index_sequence<std::tuple_size<decltype(attrs)>::value> seq;
        apply_attributes_values(attrs, attributes_to_fetch, seq);
        return attrs;
    }

  private:
    /**
     * Create a partially configured attribute template.
     *
     * The type will be set correctly, expected buffer size will be
     * set, but the buffer pointer is set later.
     *
     * The real buffer must always be bigger than the buffer size we set here.
     *
     * @tparam PKCSAttributeType
     * @return
     */
    template <CK_ATTRIBUTE_TYPE PKCSAttributeType>
    CK_ATTRIBUTE make_attr_template()
    {
        CK_ATTRIBUTE attribute_template;
        attribute_template.type = PKCSAttributeType;
        attribute_template.ulValueLen =
            Attribute<PKCSAttributeType>::VariableLengthBufferSize::value;
        attribute_template.pValue = nullptr;
        return attribute_template;
    }

    /**
     * Apply an untyped attribute value to a fixed size typed attribute.
     */
    template <typename AttributeT>
    std::enable_if_t<!AttributeT::IsDataFixedLength::value, void>
    apply_attribute_value(AttributeT &attr, CK_ATTRIBUTE untyped_attr)
    {
        attr.assign_from_bytes(static_cast<uint8_t *>(untyped_attr.pValue),
                               untyped_attr.ulValueLen);
    }

    /**
     * Apply an untyped attribute value to a variable length typed attribute.
     */
    template <typename AttributeT>
    std::enable_if_t<AttributeT::IsDataFixedLength::value, void>
    apply_attribute_value(AttributeT &attr, CK_ATTRIBUTE untyped_attr)
    {
        std::memcpy(std::addressof(attr.data_), untyped_attr.pValue,
                    untyped_attr.ulValueLen);
    }

    /**
     * Apply the attributes values fetched into `untyped_attributes` to
     * the Attribute<T> objects in the tuple.
     */
    template <typename TupleT, size_t... idx>
    void apply_attributes_values(TupleT &typed_attributes,
                                 std::vector<CK_ATTRIBUTE> untyped_attributes,
                                 std::index_sequence<idx...> index_sequence)
    {
        assert(index_sequence.size() == untyped_attributes.size());
        // Can't wait for std::apply...
        int x[] = {1, ((void)apply_attribute_value(std::get<idx>(typed_attributes),
                                                   untyped_attributes.at(idx)),
                       0)...};
        (void)x;
    }

    template <CK_ATTRIBUTE_TYPE PKCSAttributeType>
    static constexpr size_t compute_buffer_size()
    {
        return Attribute<PKCSAttributeType>::VariableLengthBufferSize::value;
    }

    /**
     * Retrieve the biggest VariableLengthBufferSize for all attributes
     * we are fetching.
     */
    template <CK_ATTRIBUTE_TYPE... PKCSAttributeType>
    static constexpr std::enable_if_t<sizeof...(PKCSAttributeType) != 1, size_t>
    compute_buffer_size()
    {
        return std::max(Attribute<PKCSAttributeType>::VariableLengthBufferSize::value...);
    }

    /**
     * Similar to native_get_attribute() but fetch multiple attributes at
     * once. It is way faster to call this function if you plan to retrieve
     * multiple attributes, as it avoid multiple network call.
     */
    std::vector<CK_ATTRIBUTE>
    native_get_attributes(std::vector<CK_ATTRIBUTE> attr_templates);

    Session &session_;
    CK_OBJECT_HANDLE handle_;
};
}
