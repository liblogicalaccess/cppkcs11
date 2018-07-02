#include <algorithm>
#include "cppkcs11/services/object_service.hpp"
#include "gtest/gtest.h"
#include "cppkcs11/cppkcs11.hpp"
#include "cppkcs11/secure_memory/secure_string.hpp"
#include "test_helper.hpp"

/**
 * Tests in this file kinda assume that other call
 * work correctly. Most feature relies on each other
 * to perform testing...
 */

class ObjectServiceTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        cppkcs::load_pkcs();
        cppkcs::initialize();

        auto session = cppkcs::open_session(NETHSM_SLOT, CKS_RW_USER_FUNCTIONS);
        session_     = std::make_unique<cppkcs::Session>(std::move(session));
        session_->login(HSM_USER_PIN);

        service_ = std::make_unique<cppkcs::ObjectService>(*session_);
    }

    void TearDown() override
    {
        // We need to null our pointers, otherwise we will finalize() before
        // objects' destruction.

        session_->logout();
        service_ = nullptr;
        session_ = nullptr;
        cppkcs::finalize();
    }

    /**
     * Create an object, doesn't matter what.
     */
    cppkcs::Object create_dummy_object()
    {
        // We create a GENERIC_SECRET instead of DATA because, in its
        // default configuration, the ATOS NetHSM doesn't allow creating
        // DATA object.
        using namespace cppkcs;
        return service_->create_object(
            make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
            make_attribute<CKA_VALUE>({1, 2, 3, 4}));
    }

    std::unique_ptr<cppkcs::Session> session_;
    std::unique_ptr<cppkcs::ObjectService> service_;
};

TEST_F(ObjectServiceTest, test_find_objects)
{
    size_t object_count = service_->find_objects().size();
    create_dummy_object();
    size_t new_object_count = service_->find_objects().size();
    ASSERT_EQ(new_object_count, object_count + 1);

    create_dummy_object();
    create_dummy_object();
    new_object_count = service_->find_objects().size();
    ASSERT_EQ(new_object_count, object_count + 3);
}

TEST_F(ObjectServiceTest, test_create_object)
{
    using namespace cppkcs;
    size_t object_count = service_->find_objects().size();

    service_->create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
                            make_attribute<CKA_VALUE>({1, 2, 3, 4}));

    ASSERT_NE(object_count, service_->find_objects().size());
}

TEST_F(ObjectServiceTest, test_destroy)
{
    size_t object_count = service_->find_objects().size();
    auto object         = create_dummy_object();
    ASSERT_NE(object_count, service_->find_objects().size());

    service_->destroy(std::move(object));
    ASSERT_EQ(object_count, service_->find_objects().size());
}

TEST_F(ObjectServiceTest, test_destroy_all)
{
    create_dummy_object();
    ASSERT_NE(0, service_->find_objects().size());

    service_->destroy_all();
    size_t object_count = service_->find_objects().size();
    ASSERT_EQ(0, object_count);
}

TEST_F(ObjectServiceTest, test_find_objects_attrs)
{
    using namespace cppkcs;
    service_->destroy_all();

    service_->create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                            make_attribute<CKA_LABEL>("GenericSecret1"),
                            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
                            make_attribute<CKA_VALUE>({1, 2, 3, 4}));

    service_->create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                            make_attribute<CKA_LABEL>("GenericSecret2"),
                            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
                            make_attribute<CKA_VALUE>({1, 2, 3, 4, 5, 6, 7, 8}));

    service_->create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                            make_attribute<CKA_LABEL>("GenericSecret3"),
                            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
                            make_attribute<CKA_VALUE>({8, 7, 6, 5, 4, 3, 2, 1}));

    size_t size =
        service_->find_objects(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY)).size();
    ASSERT_EQ(3, size);

    size = service_->find_objects(make_attribute<CKA_LABEL>("GenericSecret1")).size();
    ASSERT_EQ(1, size);

    size = service_->find_objects(make_attribute<CKA_LABEL>("GenericSecret2")).size();
    ASSERT_EQ(1, size);

    size = service_->find_objects(make_attribute<CKA_VALUE_LEN>(8)).size();
    ASSERT_EQ(2, size);
}

TEST_F(ObjectServiceTest, test_retrieve_object_attributes)
{
    using namespace cppkcs;
    service_->destroy_all();

    service_->create_object(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY),
                            make_attribute<CKA_LABEL>("GenericSecret1"),
                            make_attribute<CKA_KEY_TYPE>(KeyType::GENERIC_SECRET),
                            make_attribute<CKA_VALUE>({1, 2, 3, 4}));

    auto obj = std::move(
        service_->find_objects(make_attribute<CKA_CLASS>(ObjectType::SECRET_KEY)).at(0));
    ASSERT_EQ("GenericSecret1", obj.get_attribute<CKA_LABEL>().data_);

    // Should throw because attribute is sensitive.
    ASSERT_THROW(obj.get_attribute<CKA_VALUE>(), AttributeException);
}
