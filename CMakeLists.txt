#$cmake_minimum_required(VERSION 3.10)
cmake_minimum_required(VERSION 3.7)
project(atosnethsm)

set(CPPKCS11_ENABLE_TESTING FALSE CACHE BOOL "Build unittest for CPPKCS11")
set(CPPKCS11_ENABLE_SAMPLE FALSE CACHE BOOL "Build the sample application")
set(CPPKCS11_NATIVE_PKCS_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/native_header" CACHE STRING "Path to native PKCS11 header")

if (CPPKCS11_ENABLE_TESTING)
    find_package(GTest)
    enable_testing()
endif ()

include(${CMAKE_CURRENT_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

set(CMAKE_CXX_STANDARD 14)
if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -O2 -g -W -Wall -Wno-unused")
endif ()

if (MSVC)
#    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
#    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
endif ()

# The library
add_subdirectory(cppkcs11)

if (CPPKCS11_ENABLE_SAMPLE)
    add_executable(atosnethsm main.cpp)
    target_link_libraries(atosnethsm PUBLIC cppkcs11)
    target_include_directories(atosnethsm PUBLIC ${CPPKCS11_NATIVE_PKCS_HEADER})
endif ()

if (CPPKCS11_ENABLE_TESTING)
    add_subdirectory(test)
endif ()

# Install native PKCS11 header
file(GLOB_RECURSE NATIVE_PKCS_INCLUDEF_FILES ${CMAKE_CURRENT_SOURCE_DIR}/native_header/ "*.h")
install(FILES ${NATIVE_PKCS_INCLUDEF_FILES} DESTINATION include)
