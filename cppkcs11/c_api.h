#pragma once

#include <cstdint>
#include "cppkcs11/cppkcs11_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This header provides declarations for a few C API calls for ease of integration
 * into existing program.
 *
 * It is recommended to use the C++ API unless you have a reason to fallback
 * on the very limited C API.
 */

/**
 * Load the underlying PKCS provider library.
 *
 * Returns 0 on success, -1 on error.
 */
int CPPKCS11_EXPORT cppkcs_load_pkcs(const char *pkcs_library_path);

/**
 * Call once to initialize, at program startup or something.
 *
 * Returns 0 on success, -1 on error.
 */
int CPPKCS11_EXPORT cppkcs_initialize();

/**
 * Call once to finalize, at the end.
 *
 * Returns 0 on success, -1 on error.
 */
int CPPKCS11_EXPORT cppkcs_finalize();

/**
 * Returns 0 on success, -1 on error.
 */
int CPPKCS11_EXPORT cppkcs_generate_aes128(const char *pkcs_password, size_t hsm_slot,
                           const char *key_label, uint8_t *output_buffer);

/**
 * Returns the number of objects with the matching CKA_LABEL attributes.
 *
 * If an error occurs, this function returns -1.
 */
int CPPKCS11_EXPORT cppkcs_has_object_with_label(const char *pkcs_password, size_t hsm_slot,
                                 const char *key_label);

/**
 * Write the key value into output_buffer.
 *
 * If the dumped object's value is not a 16 bytes value this function will fail.
 * We assume that output_buffer points to a memory area of at least
 * 16 bytes.
 *
 * This functions returns 0 on success on -1 on failure.
 */
int CPPKCS11_EXPORT cppkcs_dump_key_value(const char *pkcs_password, size_t hsm_slot,
                          const char *key_label, uint8_t *output_buffer);

#ifdef __cplusplus
}
#endif
