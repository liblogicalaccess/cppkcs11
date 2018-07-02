#pragma once

#include <functional>
#include <array>
#include <type_traits>
#include <cassert>
#include <vector>
#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"

namespace cppkcs
{
class IAttribute
{
  public:
    /**
     * This method shall return a CK_ATTRIBUTE object whose type
     * and data-pointer are properly configured to represent the given
     * Attribute<T> instance.
     *
     * The CK_ATTRIBUTE returned does not perform memory management and
     * will only be valid while the Attribute<T> is alive.
     */
    virtual CK_ATTRIBUTE as_native_attribute() = 0;
};

/**
 * Base class for strongly typed attributes.
 *
 * AttributeBase defines some type traits that help
 * define the attribute:
 *   + UnderlyingPKCSAttributeId is the numerical value of the PKCS attributes, such
 *     as CKA_CLASS or CKA_LABEL.
 *   + IsDataFixedLength is a boolean that determines if we expect the attributes
 *     to be fixed length or not. For example the attribute value corresponding
 *     to CKA_CLASS is always of type CK_ATTRIBUTE_TYPE, so its data is fixed length.
 *     This is opposed to CKA_LABEL whose size may vary.
 *   + VariableLengthBufferSize is the sized of the buffer to use (if IsDataFixedLength is
 *     false) when we fetch an attribute.
 *
 * @tparam AttributeTypeId
 * @tparam ValueType
 */
template <CK_ATTRIBUTE_TYPE AttributeTypeId, typename ValueType, bool ValueFixedLength>
struct AttributeBase : public IAttribute
{
    using UnderlyingPKCSAttributeId =
        std::integral_constant<CK_ATTRIBUTE_TYPE, AttributeTypeId>;

    /**
     * If this is false, a method assign_from_bytes(uint8_t *, size_t) must be defined.
     * This method will be used to populate the value of the attribute from raw data.
     */
    using IsDataFixedLength = std::integral_constant<bool, ValueFixedLength>;

    /**
     * The default buffer size to use when fetching an attribute though
     * C_GetAttributeValue(). Subclass can override this to specify a custom
     * buffer size.
     */
    using VariableLengthBufferSize = std::integral_constant<size_t, 4096>;

    using UnderlyingValueType = ValueType;

    /**
     * Provide an implicit cast operator to cast the attribute to its underlying
     * type.
     */
    operator const ValueType &() const
    {
        return data_;
    }

    /**
     * Special case for std::string attribute type.
     * In that case, we provide a conversion operator to "const char *"
     */
    template <typename U = ValueType>
    operator std::enable_if_t<std::is_same<U, std::string>::value, const char *>() const
    {
        return data_.c_str();
    }

    ValueType data_;
};

/**
 * Base class for fixed length attributes.
 * @tparam AttributeTypeId
 * @tparam ValueType
 */
template <CK_ATTRIBUTE_TYPE AttributeTypeId, typename ValueType>
class FixedLengthAttribute : public AttributeBase<AttributeTypeId, ValueType, true>
{
  public:
    using VariableLengthBufferSize = std::integral_constant<size_t, sizeof(ValueType)>;

    CK_ATTRIBUTE as_native_attribute() override
    {
        CK_ATTRIBUTE attr;
        attr.type       = AttributeTypeId;
        attr.ulValueLen = VariableLengthBufferSize::value;
        attr.pValue     = static_cast<void *>(std::addressof(this->data_));

        return attr;
    }
};

/**
 * Base class for variable length attributes.
 * @tparam AttributeTypeId
 * @tparam ValueType
 */
template <CK_ATTRIBUTE_TYPE AttributeTypeId, typename ValueType>
class VariableLengthAttribute : public AttributeBase<AttributeTypeId, ValueType, false>
{
};

/**
 * Default Attribute class. Templated on the type.
 *
 * For each attribute the library maintainer is expected to provide a
 * specialization for the Attribute class template.
 *
 * The previously defined FixedLengthAttribute and VariableLengthAttribute
 * classes are expected to be used to ease the implementation.
 */
template <CK_ATTRIBUTE_TYPE AttributeTypeId>
class Attribute
{
};

/**
 * Create CK_ATTRIBUTEs for an arbitrary number of strongly typed attributes into
 * an std::array of CK_ATTRIBUTE.
 * Those CK_ATTRIBUTES struct are backed by the strongly typed attributes.
 */
template <typename... AttributesT>
std::array<CK_ATTRIBUTE, sizeof...(AttributesT)>
as_native_attributes(AttributesT &&... attr)
{
    std::array<CK_ATTRIBUTE, sizeof...(AttributesT)> native_attributes{
        attr.as_native_attribute()...};
    return native_attributes;
};

/**
 * Convert a vector de reference_wrapper to IAttribute object into a vector of
 * CK_ATTRIBUTE backed by those IAttributes.
 */
std::vector<CK_ATTRIBUTE>
as_native_attributes_v(const std::vector<std::reference_wrapper<IAttribute>> &attrs);

/**
 * Create a strongly typed attribute and specify its value.
 */
template <CK_ATTRIBUTE_TYPE PKCSAttributeType>
Attribute<PKCSAttributeType>
make_attribute(const typename Attribute<PKCSAttributeType>::UnderlyingValueType &value)
{
    auto attr  = Attribute<PKCSAttributeType>();
    attr.data_ = value;

    return attr;
}

/**
 * Class for attribute backed by a std::vector<uint8_t>
 */
template <CK_ATTRIBUTE_TYPE PKCSAttributeType>
class ByteVectorAttribute
    : public VariableLengthAttribute<PKCSAttributeType, std::vector<uint8_t>>
{
  public:
    using VariableLengthBufferSize = std::integral_constant<size_t, 128>;

    void assign_from_bytes(uint8_t *bytes, size_t len)
    {
        this->data_ = std::vector<uint8_t>(bytes, bytes + len);
    }

    CK_ATTRIBUTE as_native_attribute() override
    {
        CK_ATTRIBUTE attr;
        attr.type       = ByteVectorAttribute::UnderlyingPKCSAttributeId::value;
        attr.ulValueLen = this->data_.size();
        attr.pValue     = &this->data_[0];
        return attr;
    }
};

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Below are per-attribute specialization                                     //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////


/**
 * Specialization for the CKA_CLASS attribute.
 */
template <>
class Attribute<CKA_CLASS> : public FixedLengthAttribute<CKA_CLASS, ObjectType>
{
};

/**
 * Specialization for the CKA_TOKEN attribute.
 */
template <>
class Attribute<CKA_TOKEN> : public FixedLengthAttribute<CKA_TOKEN, bool>
{
};

/**
 * Specialization for the CKA_LOCAL attribute.
 */
template <>
class Attribute<CKA_LOCAL> : public FixedLengthAttribute<CKA_LOCAL, bool>
{
};


/**
 * Specialization for the CKA_EXTRACTABLE attribute.
 */
template <>
class Attribute<CKA_EXTRACTABLE> : public FixedLengthAttribute<CKA_EXTRACTABLE, bool>
{
};

/**
 * Specialization for the CKA_SENSITIVE attribute.
 */
template <>
class Attribute<CKA_SENSITIVE> : public FixedLengthAttribute<CKA_SENSITIVE, bool>
{
};

template <>
class Attribute<CKA_DERIVE> : public FixedLengthAttribute<CKA_DERIVE, bool>
{
};

template <>
class Attribute<CKA_ENCRYPT> : public FixedLengthAttribute<CKA_ENCRYPT, bool>
{
};

template <>
class Attribute<CKA_DECRYPT> : public FixedLengthAttribute<CKA_DECRYPT, bool>
{
};

/**
* Specialization for the CKA_VALUE_LEN attribute.
*/
template <>
class Attribute<CKA_VALUE_LEN> : public FixedLengthAttribute<CKA_VALUE_LEN, CK_ULONG>
{
};

/**
* Specialization for the CKA_KEY_TYPE attribute.
*/
template <>
class Attribute<CKA_KEY_TYPE> : public FixedLengthAttribute<CKA_KEY_TYPE, KeyType>
{
};

/**
 * Specialization for the CKA_LABEL attribute.
 */
template <>
class Attribute<CKA_LABEL> : public VariableLengthAttribute<CKA_LABEL, std::string>
{
  public:
    using VariableLengthBufferSize = std::integral_constant<size_t, 128>;

    void assign_from_bytes(uint8_t *bytes, size_t len)
    {
        this->data_ = std::string(bytes, bytes + len);
    }

    CK_ATTRIBUTE as_native_attribute() override
    {
        CK_ATTRIBUTE attr;
        attr.type       = UnderlyingPKCSAttributeId::value;
        attr.ulValueLen = static_cast<CK_ULONG>(this->data_.size());
        attr.pValue     = &this->data_[0];
        return attr;
    }
};

/**
 * Specialization for the CKA_ID attribute.
 */
template <>
class Attribute<CKA_ID> : public ByteVectorAttribute<CKA_ID>
{
  public:
    using VariableLengthBufferSize = std::integral_constant<size_t, 128>;
};

/**
 * Specialization for the CKA_VALUE attribute.
 */
template <>
class Attribute<CKA_VALUE> : public VariableLengthAttribute<CKA_VALUE, SecureString>
{
  public:
    using VariableLengthBufferSize = std::integral_constant<size_t, 4096>;

    void assign_from_bytes(uint8_t *bytes, size_t len)
    {
        this->data_ = SecureString(std::string(bytes, bytes + len));
    }

    CK_ATTRIBUTE as_native_attribute() override
    {
        CK_ATTRIBUTE attr;
        attr.type       = UnderlyingPKCSAttributeId::value;
        attr.ulValueLen = static_cast<CK_ULONG>(this->data_.size());
        attr.pValue     = this->data_.data();
        return attr;
    }
};
}
