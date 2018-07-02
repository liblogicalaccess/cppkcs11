#include "cppkcs11/cppkcs11.hpp"
#include "pkcs_c_wrapper.hpp"
#include "pkcsexceptions.hpp"
#include <type_traits>

namespace cppkcs
{
std::map<size_t, std::string> pkcs_error_code_to_string{
    {0x00000031, "CKR_DEVICE_MEMORY"},
    {0x00000007, "CKR_ARGUMENTS_BAD"},
    {0x000000A3, "CKR_PIN_EXPIRED"},
    {0x00000110, "CKR_WRAPPED_KEY_INVALID"},
    {0x000000E0, "CKR_TOKEN_NOT_PRESENT"},
    {0x00000060, "CKR_KEY_HANDLE_INVALID"},
    {0x00000011, "CKR_ATTRIBUTE_SENSITIVE"},
    {0x00000000, "CKR_OK"},
    {0x0000006A, "CKR_KEY_UNEXTRACTABLE"},
    {0x000000A4, "CKR_PIN_LOCKED"},
    {0x00000105, "CKR_USER_TOO_MANY_TYPES"},
    {0x00000054, "CKR_FUNCTION_NOT_SUPPORTED"},
    {0x00000041, "CKR_ENCRYPTED_DATA_LEN_RANGE"},
    {0x00000012, "CKR_ATTRIBUTE_TYPE_INVALID"},
    {0x000000B5, "CKR_SESSION_READ_ONLY"},
    {0x00000082, "CKR_OBJECT_HANDLE_INVALID"},
    {0x00000091, "CKR_OPERATION_NOT_INITIALIZED"},
    {0x00000180, "CKR_STATE_UNSAVEABLE"},
    {0x000000B0, "CKR_SESSION_CLOSED"},
    {0x000000B7, "CKR_SESSION_READ_ONLY_EXISTS"},
    {0x00000008, "CKR_NO_EVENT"},
    {0x00000050, "CKR_FUNCTION_CANCELED"},
    {0x00000065, "CKR_KEY_CHANGED"},
    {0x00000190, "CKR_CRYPTOKI_NOT_INITIALIZED"},
    {0x00000113, "CKR_WRAPPING_KEY_HANDLE_INVALID"},
    {0x000000C1, "CKR_SIGNATURE_LEN_RANGE"},
    {0x00000104, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"},
    {0x00000100, "CKR_USER_ALREADY_LOGGED_IN"},
    {0x00000115, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"},
    {0x00000102, "CKR_USER_PIN_NOT_INITIALIZED"},
    {0x0000000A, "CKR_CANT_LOCK"},
    {0x00000051, "CKR_FUNCTION_NOT_PARALLEL"},
    {0x00000103, "CKR_USER_TYPE_INVALID"},
    {0x00000006, "CKR_FUNCTION_FAILED"},
    {0x000001A0, "CKR_MUTEX_BAD"},
    {0x00000114, "CKR_WRAPPING_KEY_SIZE_RANGE"},
    {0x00000120, "CKR_RANDOM_SEED_NOT_SUPPORTED"},
    {0x00000010, "CKR_ATTRIBUTE_READ_ONLY"},
    {0x000000F0, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"},
    {0x000000D0, "CKR_TEMPLATE_INCOMPLETE"},
    {0x00000090, "CKR_OPERATION_ACTIVE"},
    {0x000000B1, "CKR_SESSION_COUNT"},
    {0x00000121, "CKR_RANDOM_NO_RNG"},
    {0x000000B4, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"},
    {0x00000009, "CKR_NEED_TO_CREATE_THREADS"},
    {0x00000200, "CKR_FUNCTION_REJECTED"},
    {0x000000C0, "CKR_SIGNATURE_INVALID"},
    {0x00000101, "CKR_USER_NOT_LOGGED_IN"},
    {0x00000130, "CKR_DOMAIN_PARAMS_INVALID"},
    {0x00000191, "CKR_CRYPTOKI_ALREADY_INITIALIZED"},
    {0x000000D1, "CKR_TEMPLATE_INCONSISTENT"},
    {0x00000030, "CKR_DEVICE_ERROR"},
    {0x00000020, "CKR_DATA_INVALID"},
    {0x00000002, "CKR_HOST_MEMORY"},
    {0x00000001, "CKR_CANCEL"},
    {0x00000069, "CKR_KEY_NOT_WRAPPABLE"},
    {0x00000068, "CKR_KEY_FUNCTION_NOT_PERMITTED"},
    {0x000000E2, "CKR_TOKEN_WRITE_PROTECTED"},
    {0x000000F1, "CKR_UNWRAPPING_KEY_SIZE_RANGE"},
    {0x000000A0, "CKR_PIN_INCORRECT"},
    {0x00000071, "CKR_MECHANISM_PARAM_INVALID"},
    {0x000000B8, "CKR_SESSION_READ_WRITE_SO_EXISTS"},
    {0x000001A1, "CKR_MUTEX_NOT_LOCKED"},
    {0x000000A1, "CKR_PIN_INVALID"},
    {0x00000063, "CKR_KEY_TYPE_INCONSISTENT"},
    {0x00000112, "CKR_WRAPPED_KEY_LEN_RANGE"},
    {0x000000B3, "CKR_SESSION_HANDLE_INVALID"},
    {0x00000150, "CKR_BUFFER_TOO_SMALL"},
    {0x000000B6, "CKR_SESSION_EXISTS"},
    {0x00000032, "CKR_DEVICE_REMOVED"},
    {0x00000064, "CKR_KEY_NOT_NEEDED"},
    {0x00000003, "CKR_SLOT_ID_INVALID"},
    {0x00000062, "CKR_KEY_SIZE_RANGE"},
    {0x00000160, "CKR_SAVED_STATE_INVALID"},
    {0x80000000, "CKR_VENDOR_DEFINED"},
    {0x00000013, "CKR_ATTRIBUTE_VALUE_INVALID"},
    {0x000000F2, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"},
    {0x00000170, "CKR_INFORMATION_SENSITIVE"},
    {0x000000A2, "CKR_PIN_LEN_RANGE"},
    {0x00000005, "CKR_GENERAL_ERROR"},
    {0x00000070, "CKR_MECHANISM_INVALID"},
    {0x00000066, "CKR_KEY_NEEDED"},
    {0x00000021, "CKR_DATA_LEN_RANGE"},
    {0x00000067, "CKR_KEY_INDIGESTIBLE"},
    {0x00000040, "CKR_ENCRYPTED_DATA_INVALID"},
    {0x000000E1, "CKR_TOKEN_NOT_RECOGNIZED"},
};

void load_pkcs(const std::string &pkcs_shared_object_path)
{
    // First we need to load the underlying PKCS library.
    // I'm not sure this is the best place, because if the init code
    // does not run we wont receive PKCS_NOT_INITIALIZED but rather
    // a brutal segfault because we are dereferencing null function pointer.

    PKCSAPI::init_function_pointers(pkcs_shared_object_path);
}

void load_pkcs()
{
    const char *pkcs_so_path = getenv("CPPKCS11_UNDERLYING_LIBRARY");
    if (!pkcs_so_path)
        throw std::runtime_error("CPPKCS11_UNDERLYING_LIBRARY environment variable not "
                                 "set. Cannot load underlying library.");
    PKCSAPI::init_function_pointers(pkcs_so_path);
}

void initialize()
{
    CK_RV ret;
    ret = PKCSAPI::initialize_(nullptr);
    throw_on_error<PKCSException>(ret, "Initialisation Error");
}

void finalize()
{
    CK_RV ret;
    ret = PKCSAPI::finalize_(nullptr);
    throw_on_error<PKCSException>(ret, "Finalization Error");
}

std::vector<CK_SLOT_ID> get_slot_list(bool token_present)
{
    CK_RV ret;
    std::vector<CK_SLOT_ID> slots;

    // First we fetch the number of slots.
    CK_ULONG number_of_slots;
    ret = PKCSAPI::get_slot_list_(token_present, nullptr, &number_of_slots);
    throw_on_error<PKCSException>(ret, "GetSlotList (Get size)");
    slots.resize(number_of_slots);

    // If there is a size mismatch between our buffer size (number_of_slots)
    // and a the new number of slots on the server, an error will be raised.
    ret = PKCSAPI::get_slot_list_(token_present, slots.data(), &number_of_slots);
    throw_on_error<PKCSException>(ret, "GetSlotList (Get data)");

    // We resize in case the number of slots is lower.
    slots.resize(number_of_slots);
    return slots;
}

CK_SLOT_INFO get_slot_info(CK_SLOT_ID slot_id)
{
    CK_RV ret;
    CK_SLOT_INFO slot_info;
    ret = PKCSAPI::get_slot_info_(slot_id, &slot_info);
    throw_on_error<GetInfoException>(ret, "GetSlotInfo", slot_id);

    return slot_info;
}

CK_TOKEN_INFO get_token_info(CK_SLOT_ID slot_id)
{
    CK_RV ret;
    CK_TOKEN_INFO token_info;
    ret = PKCSAPI::get_token_info_(slot_id, &token_info);
    throw_on_error<GetInfoException>(ret, "GetTokenInfo", slot_id);

    return token_info;
}

Session open_session(CK_SLOT_ID slot_id, CK_FLAGS flags)
{
    CK_RV ret;
    CK_SESSION_HANDLE session_handle;

    flags |= CKF_SERIAL_SESSION;
    ret = PKCSAPI::open_session_(slot_id, flags, nullptr, nullptr, &session_handle);
    throw_on_error<PKCSException>(ret, "OpenSession");

    return Session(session_handle, slot_id);
}

void close_session(CK_SESSION_HANDLE session_handle)
{
    CK_RV ret;
    ret = PKCSAPI::close_session_(session_handle);
    throw_on_error<PKCSException>(ret, "CloseSession");
}
}
