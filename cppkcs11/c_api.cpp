#include "cppkcs11/services/key_service.hpp"
#include "cppkcs11/c_api.h"
#include "cppkcs11/cppkcs11.hpp"

int cppkcs_generate_aes128(const char *pkcs_password, size_t hsm_slot,
                           const char *key_label, uint8_t *output_buffer)
{
    using namespace cppkcs;
    try
    {
        auto session = open_session(hsm_slot, CKS_RW_USER_FUNCTIONS);
        session.login(SecureString(pkcs_password));

        KeyService service(session);
        auto key = service.generate_aes_128_key(
            make_attribute<CKA_LABEL>(std::string(key_label)),
            make_attribute<CKA_TOKEN>(true), make_attribute<CKA_EXTRACTABLE>(true),
            make_attribute<CKA_SENSITIVE>(false));

        auto key_value = key.get_attribute<CKA_VALUE>().data_;
        // Copy key into provided output buffer.
        for (int i = 0; i < 16; ++i)
        {
            output_buffer[i] = *(key_value.data() + i);
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_generate_aes128 failed: " << e.what() << std::endl;
        return -1;
    }
}

int cppkcs_has_object_with_label(const char *pkcs_password, size_t hsm_slot,
                                 const char *key_label)
{
    using namespace cppkcs;
    try
    {
        auto session = open_session(hsm_slot, CKS_RW_USER_FUNCTIONS);
        session.login(SecureString(pkcs_password));

        ObjectService service(session);
        return static_cast<int>(
            service.find_objects(make_attribute<CKA_LABEL>(std::string(key_label)))
                .size());
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_has_object_with_label failed: " << e.what() << std::endl;
        return -1;
    }
}

int cppkcs_dump_key_value(const char *pkcs_password, size_t hsm_slot,
                          const char *key_label, uint8_t *output_buffer)
{
    using namespace cppkcs;
    try
    {
        auto session = open_session(hsm_slot, CKS_RW_USER_FUNCTIONS);
        session.login(SecureString(pkcs_password));

        ObjectService service(session);
        auto objects =
            service.find_objects(make_attribute<CKA_LABEL>(std::string(key_label)));

        if (objects.empty())
            return -1;

        auto &key      = objects.at(0);
        auto key_value = key.get_attribute<CKA_VALUE>().data_;

        if (key_value.size() > 16)
            return -1;
        // Copy key into provided output buffer.
        for (int i = 0; i < 16; ++i)
        {
            output_buffer[i] = *(key_value.data() + i);
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_dump_key_value failed: " << e.what() << std::endl;
        return -1;
    }
}

int cppkcs_load_pkcs(const char *pkcs_library_path)
{
    try
    {
        if (pkcs_library_path != nullptr)
            cppkcs::load_pkcs(pkcs_library_path);
        else
            cppkcs::load_pkcs();
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_load_pkcs failed: " << e.what() << std::endl;
        return -1;
    }
}

int cppkcs_initialize()
{
    try
    {
        cppkcs::initialize();
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_initialize failed: " << e.what() << std::endl;
        return -1;
    }
}

int cppkcs_finalize()
{
    try
    {
        cppkcs::finalize();
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "cppkcs_finalize failed: " << e.what() << std::endl;
        return -1;
    }
}
