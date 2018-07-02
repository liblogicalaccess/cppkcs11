/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.1 $ */
/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */
#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

#if defined (OPENSSL_SYS_WIN32) || defined (CK_Win32) || defined (WIN32)
#pragma pack(push, cryptoki, 1)

/* Specifies that the function is a DLL entry point. */
#define CK_IMPORT_SPEC __declspec(dllimport)

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
 * not define it in applications.
 */
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif

/* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  CK_EXPORT_SPEC returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  CK_EXPORT_SPEC returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_PTR name)

#elif defined(OPENSSL_SYSNAME_WIN16) || defined (CK_Win16) || defined (WIN16)
#pragma pack(push, cryptoki, 1)

#pragma pack(1)

#define CK_PTR far *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType __export _far _pascal name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType __export _far _pascal name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType __export _far _pascal (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType _far _pascal (* name)

#else /* UNIX, Linux, AIX */

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#endif /* OS Type */

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#if defined (OPENSSL_SYS_WIN32) || defined (CK_Win32) || defined (WIN32)
#pragma pack(pop, cryptoki)
#endif

#if defined(OPENSSL_SYSNAME_WIN16) || defined (CK_Win16) || defined (WIN16)
#pragma pack(pop, cryptoki)
#endif

#endif /* ___CRYPTOKI_H_INC___ */

