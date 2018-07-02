#include <cstddef>
#include <cstdint>
#include <string>
#include <cstring>
#include "cppkcs11/secure_memory/memory_tools.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"

namespace cppkcs
{

SecureString::SecureString()
    : buffer_(0)
{
}

SecureString::SecureString(std::initializer_list<uint8_t> bytes)
    : buffer_(bytes.size())
{
    std::memcpy(buffer_.data(), bytes.begin(), bytes.size());
    // Sadly we cannot bzero an initializer_list.
}

SecureString::SecureString(std::string &&o)
    : buffer_(o.size())
{
    std::memcpy(buffer_.data(), o.data(), o.size());
    secure_bzero(o);
}

SecureString::SecureString(const char *str)
    : buffer_(std::strlen(str))
{
    std::memcpy(buffer_.data(), str, strlen(str));
    // Do not bzero, might be a string literal.
}

SecureString::SecureString(const uint8_t *ptr, size_t len)
    : buffer_(len)
{
    std::memcpy(buffer_.data(), ptr, len);
}
}
