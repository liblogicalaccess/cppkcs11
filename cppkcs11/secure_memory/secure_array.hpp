#pragma once

#include <array>
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "cppkcs11/secure_memory/memory_tools.hpp"

namespace cppkcs
{

/**
 * SecureArray is wrapper around std::array<> that clear memory
 * on destruction.
 */
template <typename T, size_t ArraySize>
class SecureArray
{
  public:
    ~SecureArray()
    {
        if (size())
            secure_bzero(data(), size());
    }

    size_t size() const
    {
        return underlying_.size();
    }

    T *data()
    {
        return underlying_.data();
    }

  private:
    std::array<T, ArraySize> underlying_;
};
}
