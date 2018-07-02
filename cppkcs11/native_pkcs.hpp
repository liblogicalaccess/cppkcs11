#pragma once

/**
* The PKCS11 header requires that some platform specific macro be defined.
 *
 * So here we go...
*/

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION(returnType, name) returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#define NULL_PTR nullptr

// Finally include the native PKCS header.
#include "pkcs11.h"

namespace cppkcs
{
// Some PKCS #define converted in strongly typed enums
// for more type safety.

/**
 * Object Type. This is the value for the CKA_CLASS
 * attribute I believe.
 */
enum class ObjectType : CK_OBJECT_CLASS
{
    DATA              = 0x00000000,
    CERTIFICATE       = 0x00000001,
    PUBLIC_KEY        = 0x00000002,
    PRIVATE_KEY       = 0x00000003,
    SECRET_KEY        = 0x00000004,
    HW_FEATURE        = 0x00000005,
    DOMAIN_PARAMETERS = 0x00000006,
    MECHANISM         = 0x00000007,
    VENDOR_DEFINED    = 0x80000000
};

enum class KeyType : CK_KEY_TYPE
{
    /* the following key types are defined: */
    RSA = 0x00000000,
    DSA = 0x00000001,
    DH  = 0x00000002,

    /* ECDSA and KEA are new for v2.0 */
    /* ECDSA is deprecated in v2.11, EC is preferred. */
    ECDSA    = 0x00000003,
    EC       = 0x00000003,
    X9_42_DH = 0x00000004,
    KEA      = 0x00000005,

    GENERIC_SECRET = 0x00000010,
    RC2            = 0x00000011,
    RC4            = 0x00000012,
    DES            = 0x00000013,
    DES2           = 0x00000014,
    DES3           = 0x00000015,

    /* all these key types are new for v2.0 */
    CAST  = 0x00000016,
    CAST3 = 0x00000017,
    /* CAST5 is deprecated in v2.11, CAST128 is preferred. */
    CAST5    = 0x00000018,
    CAST128  = 0x00000018,
    RC5      = 0x00000019,
    IDEA     = 0x0000001A,
    SKIPJACK = 0x0000001B,
    BATON    = 0x0000001C,
    JUNIPER  = 0x0000001D,
    CDMF     = 0x0000001E,
    AES      = 0x0000001F,
};
}
