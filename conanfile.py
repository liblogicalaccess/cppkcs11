from conans import ConanFile, CMake, tools

class CPPKCS11Conan(ConanFile):
    name = "cppkcs11"
    version = "1.2"
    license = ""
    url = "https://github.com/islog/liblogicalaccess"
    description = "C++ PKCS11 Wrapper"
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake", "cmake_find_package"
    exports_sources = "*"

    def build_requirements(self):
        self.build_requires('gtest/1.15.0')

    def configure_cmake(self):
        cmake = CMake(self, build_type=self.settings.build_type)
        cmake.definitions['CPPKCS11_ENABLE_TESTING'] = True
        cmake.configure()
        return cmake

    def build(self):
        cmake = self.configure_cmake()
        cmake.build()

    def package(self):
        cmake = self.configure_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs.append('cppkcs11')
