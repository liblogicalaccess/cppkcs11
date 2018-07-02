set(CPPKCS11_HEADERS "")

set(CPPKCS11_SRCS
        ${CMAKE_CURRENT_SOURCE_DIR}/cppkcs11.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcsexceptions.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/session.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/object.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/attribute.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs_c_wrapper.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/services/object_service.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/services/key_service.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/services/crypto_service.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/secure_memory/memory_tools.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/secure_memory/secure_string.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/secure_memory/secure_array.cpp
        )

add_library(cppkcs11 STATIC ${CPPKCS11_SRCS} ${CPPKCS11_HEADERS})

target_include_directories(cppkcs11 PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CPPKCS11_NATIVE_PKCS_HEADER})

if(UNIX)
    target_link_libraries(cppkcs11 PUBLIC dl)
endif()
