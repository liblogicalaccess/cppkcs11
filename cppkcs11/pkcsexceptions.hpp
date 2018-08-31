#pragma once

#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/cppkcs11_export.h"
#include <stdexcept>
#include <string>

namespace cppkcs
{

/**
 * Base class for PKCS related exception raised by the library.
 */
class CPPKCS11_EXPORT PKCSException : public std::runtime_error
{
  public:
    explicit PKCSException(CK_RV errcode, const std::string &what);

  protected:
    /**
     * The error code at the source of the exception.
     */
    CK_RV error_code_;
};

/**
 * Exception raised when retrieve slot / token information fails.
 */
class CPPKCS11_EXPORT GetInfoException : public PKCSException
{
  public:
    /**
     * @param slot_id The slotID for which we failed to retrieve information.
     */
    explicit GetInfoException(CK_RV errcode, const std::string &what, CK_SLOT_ID slot_id);

    static std::string build_msg(const std::string &what, CK_SLOT_ID slot_id);
};

/**
 * Exception related to attribute value.
 *
 * It is possible that the PKCS error code be SUCCESS even though this
 * exception is thrown.
 *
 * This is because we throw this exception when the size returned for an
 * attribute
 * is -1, indicating an issue.
 */
class CPPKCS11_EXPORT AttributeException : public PKCSException
{
  public:
    explicit AttributeException(CK_RV errcode, const std::string &what);
};
}
