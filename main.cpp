#include "cppkcs11/attribute.hpp"
#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/cppkcs_fwd.hpp"
#include "cppkcs11/pkcsexceptions.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include <array>
#include <cppkcs11/services/crypto_service.hpp>
#include <cppkcs11/services/key_service.hpp>
#include <cppkcs11/services/object_service.hpp>
#include <iostream>
#include <map>
#include <tuple>

#define MY_HSM_PIN cppkcs::SecureString("")

void test_object(cppkcs::Session &session, cppkcs::Object &object)
{
    try
    {
        cppkcs::Attribute<CKA_CLASS> attr_class;
        cppkcs::Attribute<CKA_LABEL> attr_label;

        std::tie(attr_class, attr_label) = object.get_attributes<CKA_CLASS, CKA_LABEL>();

        // attr_label = object.get_attribute<CKA_LABEL>();
        // std::cout << "ATTRIBUTE CLASS: " << attr_class.data_ << std::endl;
        std::cout << "ATTRIBUTE LABEL: " << attr_label.data_ << std::endl;

        if (attr_class.data_ == cppkcs::ObjectType::SECRET_KEY)
        {
            if (object.get_attribute<CKA_KEY_TYPE>().data_ == cppkcs::KeyType::AES)
            {
                std::cout << "We got an AES key of size: "
                          << object.get_attribute<CKA_VALUE_LEN>() << std::endl;
            }
            else
            {
                std::cout << "Key type: "
                          << (size_t)object.get_attribute<CKA_KEY_TYPE>().data_
                          << std::endl;
            }
        }
        else
        {
            std::cout << "Object of type:" << (size_t)attr_class.data_ << std::endl;
        }
    }
    catch (const cppkcs::PKCSException &e)
    {
        std::cout << "Failed to get info about object: " << object.native_handle()
                  << ". Error: " << e.what() << std::endl;
    }
}

void test_slot(CK_SLOT_ID slot_id)
{
    using namespace cppkcs;
    Session session = open_session(slot_id, CKF_RW_SESSION);
    session.login(MY_HSM_PIN);
    ObjectService os(session);

    CK_MECHANISM mechanism;
    mechanism.mechanism      = CKM_AES_KEY_GEN;
    mechanism.pParameter     = nullptr;
    mechanism.ulParameterLen = 0;

    KeyService ks(session);
    auto key = ks.generate_key(
        mechanism, make_attribute<CKA_LABEL>("My Key"), make_attribute<CKA_TOKEN>(true),
        make_attribute<CKA_VALUE_LEN>(32), make_attribute<CKA_ID>({1, 2, 3, 4}));
    // session.generate_key(mechanism);
    // key.destroy();

    for (auto &object : os.find_objects({}))
    {
        std::cout << "Found object with handle: " << object.native_handle() << std::endl;
        test_object(session, object);
        // break;
        // object.destroy();
    }
}

void test_find_object()
{
    using namespace cppkcs;

    Session session = open_session(7, 0); //, CKF_RW_SESSION);
    session.login(MY_HSM_PIN);
    // Session session = open_session(1981080426, CKF_RW_SESSION);
    // session.login(cppkcs::SecureString("qqqq"));
    ObjectService os(session);

    for (auto &obj : os.find_objects(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY)))
    {
        std::cout << "Found: " << obj.get_attribute<CKA_LABEL>() << std::endl;
        /*        SecureString ss("1234567890ABCDEF");
                std::vector<uint8_t> iv{1, 2, 3,   4,   5,   6,   7,   8,
                                        9, 0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

                CryptoService cs(session);
                auto out = cs.aes_encrypt(ss, iv, obj);
                std::cout << std::string(out.begin(), out.end()) << std::endl;
                SecureString clear = cs.aes_decrypt(out, iv, obj);

                std::cout << "Clear: " << clear.data() << std::endl;*/
    }
}

void create_my_key()
{
    using namespace cppkcs;
    SecureString key1_value({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
    SecureString key2_value({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    Session session = open_session(7, CKF_RW_SESSION);
    session.login(MY_HSM_PIN);

    std::cout << "Connected" << std::endl;
    // Session session = open_session(1981080426, CKF_RW_SESSION);
    // session.login(cppkcs::SecureString("qqqq"));

    KeyService ks(session);
    ks.import_aes_key(key1_value, make_attribute<CKA_TOKEN>(true),
                      make_attribute<CKA_LABEL>("MyAesKey"),
                      make_attribute<CKA_ID>({'1', 't', 'o', '1', '6'}));

    ks.import_aes_key(key2_value, make_attribute<CKA_TOKEN>(true),
                      make_attribute<CKA_LABEL>("MyAesKey2"),
                      make_attribute<CKA_ID>({'z', 'e', 'r', 'o'}));
}

int main()
{
    std::cout << "Hello, World!" << std::endl;
    try
    {
        cppkcs::load_pkcs("C:/islog/AtosNetHSM/Client_Software/win32/nethsm.dll");
        // cppkcs::load_pkcs("/opt/tw_proteccio/lib/libnethsm.so");
        cppkcs::initialize();

        create_my_key();
        test_find_object();

        // clear_items();
        // test_find_object();
        // test_slot(7);

        return 1;
        for (const auto &slot_id : cppkcs::get_slot_list(false))
        {
            std::cout << "Found " << slot_id << std::endl;
            CK_SLOT_INFO slot_info   = cppkcs::get_slot_info(slot_id);
            CK_TOKEN_INFO token_info = cppkcs::get_token_info(slot_id);
            std::cout << "\tDesc: " << slot_info.slotDescription << std::endl
                      << "\tManu: " << slot_info.manufacturerID << std::endl
                      << "\tFlags: " << std::hex << slot_info.flags << std::dec
                      << std::endl
                      << "\tLabel: " << token_info.label << std::endl;

            //   test_slot(slot_id);
        }
        cppkcs::finalize();
    }
    catch (const cppkcs::PKCSException &e)
    {
        std::cout << "Something went wrong: " << e.what() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "Something went wrong: " << e.what() << std::endl;
    }
    return 0;
}
