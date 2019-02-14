set(CPPKCS11_HEADERS "")
include(GenerateExportHeader)
set(CPPKCS11_SRCS
        ${CMAKE_CURRENT_SOURCE_DIR}/c_api.cpp
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

add_library(cppkcs11 SHARED ${CPPKCS11_SRCS} ${CPPKCS11_HEADERS})

generate_export_header(cppkcs11
        EXPORT_FILE_NAME "${CMAKE_CURRENT_SOURCE_DIR}/cppkcs11_export.h")
		
target_include_directories(cppkcs11 PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CPPKCS11_NATIVE_PKCS_HEADER})
if(UNIX)
    target_link_libraries(cppkcs11 PUBLIC dl)
endif()

# Install header files
file(GLOB CPPKCS11_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/ *.hpp *.h)
install(FILES ${CPPKCS11_INCLUDE} DESTINATION include/cppkcs11)
unset(CPPKCS11_INCLUDE)

file(GLOB CPPKCS11_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/secure_memory/*.hpp)
install(FILES ${CPPKCS11_INCLUDE} DESTINATION include/cppkcs11/secure_memory)
unset(CPPKCS11_INCLUDE)

file(GLOB CPPKCS11_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/services/*.hpp)
install(FILES ${CPPKCS11_INCLUDE} DESTINATION include/cppkcs11/services)
unset(CPPKCS11_INCLUDE)

# LIB_SUFFIX is a variable configured for Windows build of LibLogicalAccess
install(TARGETS cppkcs11 RUNTIME DESTINATION bin/${LIB_SUFFIX} ARCHIVE DESTINATION lib/${LIB_SUFFIX} LIBRARY DESTINATION lib/${LIB_SUFFIX})
if (MSVC)
    install(FILES $<TARGET_PDB_FILE:cppkcs11> DESTINATION pdb/${LIB_SUFFIX} OPTIONAL)
endif ()
