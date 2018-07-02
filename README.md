# What is this ?

CPPKCS11 is a simple C++ wrapper around the C PKCS11 API.
The wrapper is not complete and implements only features needed
by [LibLogicalAccess](https://github.com/islog/liblogicalaccess).

# How to use ?

The library lives in the `cppkcs` namespace. Two calls are required
before starting to use the library. See the minimal example below.

```
// dlopen() the underlying PKCS11 library.
cppkcs::load_pkcs("/path/to/underlying/pkcs11/library.so");

// Alternatively you can call load_pkcs() without any parameters.
// In that case, the library will attempt to load a shared object
// located at ${CPPKCS11_UNDERLYING_LIBRARY} environment variable.

// Initialize PKCS11.
cppkcs::initialize();

// Log into a PKCS session.
cppkcs::Session session = cppkcs::open_session(PKCS_TOKEN_SLOT, CKF_RW_SESSION);
session.login(cppkcs::SecureString("MyPassword"));

// Import a key into the HSM.
cppkcs::KeyService ks(session);
ks.import_aes_key(key1_value, cppkcs::make_attribute<CKA_TOKEN>(true),
                  cppkcs::make_attribute<CKA_LABEL>("MyAesKey"),
                  cppkcs::make_attribute<CKA_ID>({'1', 't', 'o', '1', '6'}));
```
