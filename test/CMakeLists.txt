find_package(GTest REQUIRED)

### Note that test should be running while providing
### the PROTECCIO_CONF_DIR environment variable explicitely.

#set(GTEST_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/googletest/googletest/include)

function(create_and_add_test TEST_NAME)
    add_executable(${TEST_NAME} ${TEST_NAME}.cpp)
	set_target_properties(${TEST_NAME} PROPERTIES CXX_STANDARD 14)
    target_include_directories(${TEST_NAME}  PUBLIC ${GTEST_INCLUDE_DIRS})
	if (UNIX)
		target_link_libraries(${TEST_NAME} ${GTEST_BOTH_LIBRARIES} pthread cppkcs11)
	else()
		#target_link_libraries(${TEST_NAME} ${GTEST_BOTH_LIBRARIES} cppkcs11)
		target_link_libraries(${TEST_NAME} GTest::Main cppkcs11)
	endif()
    GTEST_ADD_TESTS(${TEST_NAME} "" ${TEST_NAME}.cpp)
endfunction()

create_and_add_test(test_session)

# test_general actually tests against some hardcoded values
# that are present when connecting to an Atos NetHSM
#create_and_add_test(test_general)
create_and_add_test(test_object_service)
create_and_add_test(test_key_service)
create_and_add_test(test_crypto_service)
create_and_add_test(test_c_api)
