#include <sstream>
#include <iomanip>
#include "cppkcs11/pkcsexceptions.hpp"
#include "cppkcs11.hpp"


namespace
{
std::string build_error_message(const std::string &base_msg, CK_RV errcode)
{
    std::string pkcs_error_string = "Unknown Error Code";
    try
    {
        pkcs_error_string = cppkcs::pkcs_error_code_to_string.at(errcode);
    }
    catch (const std::out_of_range &)
    {
    }

    std::stringstream ss;
    ss << base_msg << " (PKCS EC: "
       << "0x" << std::setfill('0') << std::setw(8) << std::hex << errcode << ": "
       << pkcs_error_string << ")";
    return ss.str();
}
}

namespace cppkcs
{
PKCSException::PKCSException(CK_RV errcode, const std::string &what)
    : runtime_error(build_error_message(what, errcode))
    , error_code_(errcode)
{
}

GetInfoException::GetInfoException(CK_RV errcode, const std::string &what,
                                   CK_SLOT_ID slot_id)
    : PKCSException(errcode, build_msg(what, slot_id))
{
}

std::string GetInfoException::build_msg(const std::string &what, CK_SLOT_ID slot_id)
{
    std::stringstream ss;
    ss << what << "(SlotID: " << slot_id << ")";
    return ss.str();
}


AttributeException::AttributeException(CK_RV errcode, const std::string &what)
    : PKCSException(errcode, what)
{
}
}
