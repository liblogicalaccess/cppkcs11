from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMakeDeps, CMake, cmake_layout

class CPPKCS11Conan(ConanFile):
    name = "cppkcs11"
    version = "1.2"
    license = ""
    url = "https://github.com/liblogicalaccess/liblogicalaccess"
    description = "C++ PKCS11 Wrapper"
    settings = "os", "compiler", "build_type", "arch"
    exports_sources = "*"

    def build_requirements(self):
        self.test_requires('gtest/1.15.0')
        
    def layout(self):
        cmake_layout(self)
    
    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()
        
        deps = CMakeDeps(self)
        deps.generate()     

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs.append('cppkcs11')
