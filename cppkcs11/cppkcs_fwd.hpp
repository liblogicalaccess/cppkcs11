#pragma once

#include <cstdint>
#include <vector>
#include "cppkcs11/cppkcs11_export.h"

namespace cppkcs
{
class Session;
class Object;
class SecureString;
class IAttribute;

class ObjectService;
class KeyService;

using ByteVector = std::vector<uint8_t>;
}
