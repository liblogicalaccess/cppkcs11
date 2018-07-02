#pragma once

#include "cppkcs11/secure_memory/memory_tools.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace cppkcs
{
/**
 * A very simple object to securely encapsulate a string.
 *
 * The SecureString relies on the SecureMemoryLockedBuffer to
 * provide storage.
*/
class SecureString
{
  public:
    /**
     * Create an empty secure string.
     */
    SecureString();

    SecureString(const SecureString &) = default;

    SecureString(SecureString &&) = default;

    SecureString &operator=(const SecureString &) = default;
    SecureString &operator=(SecureString &&) = default;

    /**
     * Construction from an initializer_list of bytes.
     *
     * !! This is not secure because the binary string will be available
     * in the binary !!
     */
    SecureString(std::initializer_list<uint8_t> bytes);

    /**
     * Construct a SecureString from a std::string rvalue reference.
     *
     * We copy the string object, and then securely clear it.
     * THIS IS THE PREFERRED CONSTRUCTOR.
     */
    explicit SecureString(std::string &&o);

    /**
     * Create a SecureString from a class C string.
     *
     * IMPORTANT: The input `str` is copied into the secure string,
     * but, as opposed to SecureString(std::string &&) the input buffer
     * is not clear.
     * It is the responsibility of the caller to, if they so wish, wipe
     * the input string used to construct the SecureString.
     *
     * If the "const char *" is a string literal, this constructor
     * is not secure because the string will be available from the binary.
     */
    explicit SecureString(const char *str);

    /**
     * Construct from a blob of data.
     *
     * Does not take ownership and does not clear the source.
     */
    explicit SecureString(const uint8_t *ptr, size_t len);

    ~SecureString() = default;

    const uint8_t *data() const
    {
        return buffer_.data();
    }

    uint8_t *data()
    {
        return buffer_.data();
    }

    size_t size() const
    {
        return buffer_.size();
    }

    bool operator==(const SecureString &o) const
    {
        return o.buffer_ == buffer_;
    }

  private:
    SecureMemoryLockedBuffer buffer_;
};
}
