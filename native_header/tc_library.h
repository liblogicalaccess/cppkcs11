/** @file
    Fichier d'interface avec la lib PKCS11.
*/

#ifndef TC_LIBRARY_H
#define TC_LIBRARY_H

#include "pca4_common.h"
#include "tc_user_lib.h"
#include "tc_driver.h"

#define TC_PCI_BUF_MAX_SZ	0x3800

#define TC_DATA         0   /**< message de l'application sur le driver host                        */
#define TC_CLOSE_FD     1   /**< message de fermeture genere par le driver host                     */

/******************************************* 
        Function ID sur un short
********************************************/
//#define TC_CREATE_OBJECT                      (short)1
#define TC_DESTROY_OBJECT                     (short)2
#define TC_GET_SENSITIVE_ATTRIBUTES           (short)3
#define TC_SET_ATTRIBUTE_VALUE                (short)4
//#define TC_CRYPTO_AES                         (short)5
//#define TC_CRYPTO_SHA                         (short)6    // PCA4 SHA1, SHA256, SHA384, SHA512
//#define TC_CRYPTO_DES3                        (short)7
#define TC_CRYPTO_DES                         (short)7    // PCA4 support DES et DES3 (eventuellement avec cles DES2)
#define TC_CRYPTO_MD5                         (short)8
//#define TC_AES_ENCRYPT_AND_SHA_SIGN           (short)9
//#define TC_SHA_VERIFY_AND_AES_DECRYPT         (short)10
//#define TC_DES3_ENCRYPT_AND_MD5_SIGN          (short)11
//#define TC_MD5_VERIFY_AND_DES3_DECRYPT        (short)12
#define TC_GENERATE_KEY                       (short)13
#define TC_GENERATE_KEY_PAIR                  (short)14
#define TC_ENCRYPT                            (short)15
#define TC_DECRYPT                            (short)16
#define TC_SIGN                               (short)17
#define TC_VERIFY                             (short)18
#define TC_WRAP_KEY                           (short)19
#define TC_UNWRAP_KEY                         (short)20
#define TC_GENERATE_RANDOM                    (short)21
#define TC_GET_TOKEN_STATUS                   (short)22
#define TC_GET_CONFIGURATION                  (short)23
#define TC_SET_CONFIGURATION                  (short)24
#define TC_GET_BEGIN_TOKEN_OBJECTS            (short)25
#define TC_GET_NEXT_TOKEN_OBJECTS             (short)26
#define TC_START_PERSONALIZE                  (short)27
#define TC_SOFTWARE_UPDATE_BEGIN              (short)28
#define TC_SOFTWARE_UPDATE_NEXT               (short)29
#define TC_DESINSTALL_TOKEN                   (short)30
#define TC_DEPERSONALIZE_TOKEN                (short)31
//#define TC_TEST_TOKEN                         (short)32
#define TC_SECURITY_REPORT                    (short)33
#define TC_SAVE_KEY_NEXT                      (short)34
//#define TC_CLEAR_SECURITY_REPORT              (short)35
#define TC_TEST_ECHO                          (short)37
//#define TC_KEYBOARD_CONTROL                   (short)38
//#define TC_KEYBOARD_STRING                    (short)39
//#define TC_RESET_SMART_CARD                   (short)40  // PCA4 -
#define TC_GET_SLOT_LIST					  (short)40
#define TC_CREATE_INSTALL_SECRET			  (short)41
//#define TC_SMART_CARD_ACCESS                  (short)41  // PCA4 -
//#define TC_GET_MODE                           (short)42
//#define TC_MAKE_WAIT_START_MSG                (short)43  // PCA4 -
//#define TC_ENABLE_TOKEN                       (short)44  // PCA4 -
#define TC_SET_DATE                           (short)45  // PCA4 -
#define TC_SET_PROFIL                         (short)46
//#define TC_HASH_FLASH                         (short)47  // PCA4 -
//#define TC_SET_STATE                          (short)48
//#define TC_SET_CIK_MODE                       (short)49  // PCA4 -
//#define TC_CLOSE_APPLICATION                  (short)50
//#define TC_SET_DELAYED_WRITE                  (short)51  // PCA4 ?
//#define TC_RESET_DELAYED_WRITE                (short)52  // PCA4 ?
#define TC_LOGIN                              (short)53
#define TC_LOGOUT                             (short)54
#define TC_CREATE_BIG_OBJECT                  (short)55
#define TC_SET_BIG_OBJECT_ATTRIBUTES          (short)56
//#define TC_REINIT_CIK                         (short)57  // PCA4 -
//#define TC_GET_DISK_LUNS_ATTRIBUTES           (short)58  // PCA4 -
//#define TC_FORMAT_DISK_LUNS                   (short)59  // PCA4 -
//#define TC_SET_LUN_STATE                      (short)60  // PCA4 -
//#define TC_CREATE_RSA_LUN_KEY                 (short)61  // PCA4 -
//#define TC_BUILD_LUN_BEGIN                    (short)62  // PCA4 -
//#define TC_COPY_OBJECT                        (short)63
//#define TC_DUMP                               (short)64  // PCA4 ?
//#define TC_GET_MECH_LIST                      (short)65
#define TC_GET_MECH_INFO                      (short)66
//#define TC_SET_AUTHORIZED_SN                  (short)67  // PCA4 -
//#define TC_SET_KEY                            (short)68  // PCA4 -
//#define TC_DERIVE_KEY                         (short)69  // PCA4 -
#define TC_GET_DATE                           (short)70  // PCA4 ?
#define TC_GENKEYPAIR_BIG_OBJECT              (short)71
//#define TC_GET_OBJECT_ATTRIBUTES              (short)72
#define TC_RESTORE_KEY_NEXT                   (short)73
#define TC_SAVE_KEY                           (short)74
#define TC_RESTORE_KEY                        (short)75
#define TC_GET_BIG_SENSITIVE_ATTRIBUTES       (short)76
//#define TC_UPDATE_PROFIL                      (short)77

// PCA4 VERIFICATION SIGNATURE (ECC) LINUX
#define TC_HOST_VERIFY_INIT				(short)78
#define TC_HOST_VERIFY_UPDATE			(short)79
#define TC_HOST_VERIFY_FINAL 			(short)80
#define TC_HOST_GET_CONFIG	 			(short)81
#define TC_HOST_SET_CONFIG	 			(short)82

#define TC_GENERATE_EC_KEY_PAIR               (short)83   // PCA4_NEW
#define TC_GET_LOG			                  (short)84   // PCA4_NEW

#define TC_SO_MASTER_LOGIN			          (short)85   // PCA4_NEW
#define TC_SIGN_INIT_ECKCDSA                  (short)86   // PCA4_NEW
#define TC_AUDIT_MASTER_LOGIN	              (short)87   // PCA4_NEW
#define TC_AUDIT_MASTER_LOGOUT	              (short)88   // PCA4_NEW
#define TC_SO_MASTER_LOGOUT	              	  (short)89   // PCA4_NEW
#define TC_AUDIT_LOGOUT	              		  (short)90   // PCA4_NEW
#define TC_AUDIT_LOGIN	              		  (short)91   // PCA4_NEW
//#define TC_SSL_GENERATE_PRE_MASTER_SECRET	  (short)92	  // PCA4_NEW
//#define TC_SSL_GENERATE_MASTER_SECRET         (short)93   // PCA4_NEW
//#define TC_SSL_DERIVE_MASTER_SECRET           (short)94   // PCA4_NEW
#define TC_VERIFY_INIT_ECKCDSA                (short)95   // PCA4_NEW
#define TC_PCA2_RESTORE_SECRET             	  (short)96   // PCA4_NEW
#define TC_PCA2_DERIVE_CRX               	  (short)97   // PCA4_NEW
#define TC_PCA4_DERIVE_MASTER_KEY             (short)98   // PCA4_NEW
#define TC_DUPLICATE_CARD                     (short)99   // PCA4_NEW
#define TC_DERIVE_VPNC               	      (short)100   // PCA4_NEW

//#define TC_CRYPTO_DES_ENCRYPT                 (short)126
//#define TC_CRYPTO_DES_DECRYPT                 (short)127
#define TC_CRYPTO_AES_ENCRYPT                 (short)128
#define TC_CRYPTO_AES_DECRYPT                 (short)129
#define TC_CRYPTO_SHA1                        (short)130
#define TC_CRYPTO_SHA256                      (short)131
#define TC_CRYPTO_SHA384                      (short)132
#define TC_CRYPTO_SHA512                      (short)133

#define TC_CRYPTO_AES_CMAC                    (short)140
#define TC_m_is_AES_or_SHA(c) ((c) >= TC_CRYPTO_AES_ENCRYPT && (c) <= TC_CRYPTO_SHA512)
#define TC_m_is_AES(c)        ((c) == TC_CRYPTO_AES_ENCRYPT || (c) == (TC_CRYPTO_AES_DECRYPT))

#define TC_CRYPTO_AES_DERIVE                  (short)150

#define TC_CRYPTO_ECDH1_DERIVE                (short)151

#define TC_CRYPTO_TLS_MASTER_KEY_DH_DERIVE      (short)152
#define TC_CRYPTO_TLS_KEY_AND_MAC_DERIVE        (short)153

//#define TC_CONFIGURATION_HSM                  (short)192

#define TC_PCA2_RESTORE_KEY                   (short)0xc0c
#define TC_START_PCA2_RESTORE_KEY             (short)0xc00
#define TC_CREATE_TOKEN		                  (short)0x333
//#define TC_INSTALL_TOKEN	                  (short)0x33c
#define TC_FINISH_PERSONALIZE                 (short)0x3cc
#define TC_START_TOKEN  	                  (short)0xfff

#define TC_HSM_SLOT  10 /* slot representant le HSM PCA4 */
			   
/******************************************* 
        Offsets et longueurs
********************************************/
#define AES_ENCRYPT_SHA_SIGN_IV_OFFSET        32
#define AES_ENCRYPT_IV_OFFSET                 32
#define SHA_VERIFY_AND_AES_DECRYPT_IV_OFFSET  60
#define TC_MAX_PINLEN                         128
#define TC_DATA_LEN                           4
#define TC_SSL_MAX_CLIENT_RANDOM_LEN	  	  32  
#define TC_SSL_MAX_SERVER_RANDOM_LEN	  	  32  
#define TC_SSL_MAX_IV_LEN				  	  16  

#define TC_LG_MAX_AES_AUTOMATON               (0x8000 - 16) // 32K - 16 (octets)
#define TC_LG_MAX_SHA_AUTOMATON               (0x8000 - 64)  // 32K -  64 (octets)
#define TC_LG_MAX_RNG_AUTOMATON               (0x1000 - 4)  //  4K -  4 (octets)

/************************************************************ 
       Attributs pkcs#11 booleens du champ "attributes"
*************************************************************/
/*******************************************************************************
PCA4_NEW
Conversion des attributs BOOLEENS
Chaque attribut est maintenant represente par 4 bits (a 1 si TRUE, a 0 si FALSE)
L'ensemble de ces attributs est donc represente par 4 INT au lieu de 1
Nouveux attributs BOOLEENS : CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_AUTHENTICATE, CKA_AUTHENTICATED (attribut interne)
********************************************************************************/
#define TC_ATTR_TOKEN                         0x80000000  // PCA4 ==> bits 3 a 0 du premier INT
#define TC_ATTR_PRIVATE                       0x40000000  // PCA4 ==> bits 7 a 4 du premier INT
#define TC_ATTR_MODIFIABLE                    0x20000000  // PCA4 ==> bits 11 a 8 du premier INT
#define TC_ATTR_DERIVE                        0x10000000  // PCA4 ==> bits 15 a 12 du premier INT
#define TC_ATTR_LOCAL                         0x08000000  // PCA4 ==> bits 19 a 16 du premier INT
#define TC_ATTR_SENSITIVE                     0x04000000  // PCA4 ==> bits 23 a 20 du premier INT
#define TC_ATTR_ALWAYS_SENSITIVE              0x02000000  // PCA4 ==> bits 27 a 24 du premier INT
#define TC_ATTR_ENCRYPT                       0x01000000  // PCA4 ==> bits 31 a 28 du premier INT
#define TC_ATTR_DECRYPT                       0x00800000  // PCA4 ==> bits 3 a 0 du deuxieme INT
#define TC_ATTR_SIGN                          0x00400000  // PCA4 ==> bits 7 a 4 du deuxieme INT
#define TC_ATTR_SIGN_RECOVER                  0x00200000  // PCA4 ==> bits 11 a 8 du deuxieme INT
#define TC_ATTR_VERIFY                        0x00100000  // PCA4 ==> bits 15 a 12 du deuxieme INT
#define TC_ATTR_VERIFY_RECOVER                0x00080000  // PCA4 ==> bits 19 a 16 du deuxieme INT
#define TC_ATTR_WRAP                          0x00040000  // PCA4 ==> bits 23 a 20 du deuxieme INT
#define TC_ATTR_UNWRAP                        0x00020000  // PCA4 ==> bits 27 a 24 du deuxieme INT
#define TC_ATTR_EXTRACTABLE                   0x00010000  // PCA4 ==> bits 31 a 28 du deuxieme INT
#define TC_ATTR_NEVER_EXTRACTABLE             0x00008000  // PCA4 ==> bits 3 a 0 du troisieme INT
#define TC_ATTR_TRUSTED                       0x00004000  // PCA4 ==> bits 7 a 4 du troisieme INT
#define TC_ATTR_WRAP_WITH_TRUSTED             0x00002000  // PCA4 ==> bits 11 a 5 du troisieme INT
#define TC_ATTR_AUTHENTICATE                  0x00001000  // PCA4 ==> bits 15 a 12 du troisieme INT
//     Attributs internes booleens du champ "attributes"
#define TC_ATTR_ALWAYS_AUTHENTICATE           0x00000002  // PCA4 ==> bits 27 a 24 du quatrieme INT
#define TC_ATTR_CREATING                      0x00000001  // PCA4 ==> bits 31 a 28 du quatrieme INT

#define TC_m_ATTR_IDX_W(n)  ((n) / 8)
#define TC_m_ATTR_IDX_Q(n)  (((n) % 8) * 4)
#define TC_m_ATTR_MSK_Q(n)  (0xF << TC_m_ATTR_IDX_Q(n))
#define TC_m_ATTR_SET(a, n) (a[TC_m_ATTR_IDX_W(n)] |= TC_m_ATTR_MSK_Q(n))
#define TC_m_ATTR_TST(a, n) (((a[TC_m_ATTR_IDX_W(n)] & TC_m_ATTR_MSK_Q(n)) == TC_m_ATTR_MSK_Q(n)) ? 1 : 0)
#define TC_m_ATTR_RAZ(a, n) (a[TC_m_ATTR_IDX_W(n)] &= ~TC_m_ATTR_MSK_Q(n))

#define TC_set_ATTR_TOKEN(a)                  TC_m_ATTR_SET(a, 0)
#define TC_raz_ATTR_TOKEN(a)                  TC_m_ATTR_RAZ(a, 0)
#define TC_is_ATTR_TOKEN(a)                   TC_m_ATTR_TST(a, 0)
#define TC_set_ATTR_PRIVATE(a)                TC_m_ATTR_SET(a, 1)
#define TC_raz_ATTR_PRIVATE(a)                TC_m_ATTR_RAZ(a, 1)
#define TC_is_ATTR_PRIVATE(a)                 TC_m_ATTR_TST(a, 1)
#define TC_set_ATTR_MODIFIABLE(a)             TC_m_ATTR_SET(a, 2)
#define TC_raz_ATTR_MODIFIABLE(a)             TC_m_ATTR_RAZ(a, 2)
#define TC_is_ATTR_MODIFIABLE(a)              TC_m_ATTR_TST(a, 2)
#define TC_set_ATTR_DERIVE(a)                 TC_m_ATTR_SET(a, 3)
#define TC_raz_ATTR_DERIVE(a)                 TC_m_ATTR_RAZ(a, 3)
#define TC_is_ATTR_DERIVE(a)                  TC_m_ATTR_TST(a, 3)
#define TC_set_ATTR_LOCAL(a)                  TC_m_ATTR_SET(a, 4)
#define TC_raz_ATTR_LOCAL(a)                  TC_m_ATTR_RAZ(a, 4)
#define TC_is_ATTR_LOCAL(a)                   TC_m_ATTR_TST(a, 4)
#define TC_set_ATTR_SENSITIVE(a)              TC_m_ATTR_SET(a, 5)
#define TC_raz_ATTR_SENSITIVE(a)              TC_m_ATTR_RAZ(a, 5)
#define TC_is_ATTR_SENSITIVE(a)               TC_m_ATTR_TST(a, 5)
#define TC_set_ATTR_ALWAYS_SENSITIVE(a)       TC_m_ATTR_SET(a, 6)
#define TC_raz_ATTR_ALWAYS_SENSITIVE(a)       TC_m_ATTR_RAZ(a, 6)
#define TC_is_ATTR_ALWAYS_SENSITIVE(a)        TC_m_ATTR_TST(a, 6)
#define TC_set_ATTR_ENCRYPT(a)                TC_m_ATTR_SET(a, 7)
#define TC_raz_ATTR_ENCRYPT(a)                TC_m_ATTR_RAZ(a, 7)
#define TC_is_ATTR_ENCRYPT(a)                 TC_m_ATTR_TST(a, 7)

#define TC_set_ATTR_DECRYPT(a)                TC_m_ATTR_SET(a, 8)
#define TC_raz_ATTR_DECRYPT(a)                TC_m_ATTR_RAZ(a, 8)
#define TC_is_ATTR_DECRYPT(a)                 TC_m_ATTR_TST(a, 8)
#define TC_set_ATTR_SIGN(a)                   TC_m_ATTR_SET(a, 9)
#define TC_raz_ATTR_SIGN(a)                   TC_m_ATTR_RAZ(a, 9)
#define TC_is_ATTR_SIGN(a)                    TC_m_ATTR_TST(a, 9)
#define TC_set_ATTR_SIGN_RECOVER(a)           TC_m_ATTR_SET(a, 10)
#define TC_raz_ATTR_SIGN_RECOVER(a)           TC_m_ATTR_RAZ(a, 10)
#define TC_is_ATTR_SIGN_RECOVER(a)            TC_m_ATTR_TST(a, 10)
#define TC_set_ATTR_VERIFY_RECOVER(a)         TC_m_ATTR_SET(a, 11)
#define TC_raz_ATTR_VERIFY_RECOVER(a)         TC_m_ATTR_RAZ(a, 11)
#define TC_is_ATTR_VERIFY_RECOVER(a)          TC_m_ATTR_TST(a, 11)
#define TC_set_ATTR_WRAP(a)                   TC_m_ATTR_SET(a, 12)
#define TC_raz_ATTR_WRAP(a)                   TC_m_ATTR_RAZ(a, 12)
#define TC_is_ATTR_WRAP(a)                    TC_m_ATTR_TST(a, 12)
#define TC_set_ATTR_UNWRAP(a)                 TC_m_ATTR_SET(a, 13)
#define TC_raz_ATTR_UNWRAP(a)                 TC_m_ATTR_RAZ(a, 13)
#define TC_is_ATTR_UNWRAP(a)                  TC_m_ATTR_TST(a, 13)
#define TC_set_ATTR_EXTRACTABLE(a)            TC_m_ATTR_SET(a, 14)
#define TC_raz_ATTR_EXTRACTABLE(a)            TC_m_ATTR_RAZ(a, 14)
#define TC_is_ATTR_EXTRACTABLE(a)             TC_m_ATTR_TST(a, 14)
#define TC_set_ATTR_NEVER_EXTRACTABLE(a)      TC_m_ATTR_SET(a, 15)
#define TC_raz_ATTR_NEVER_EXTRACTABLE(a)      TC_m_ATTR_RAZ(a, 15)
#define TC_is_ATTR_NEVER_EXTRACTABLE(a)       TC_m_ATTR_TST(a, 15)

#define TC_set_ATTR_VERIFY(a)                 TC_m_ATTR_SET(a, 16)
#define TC_raz_ATTR_VERIFY(a)                 TC_m_ATTR_RAZ(a, 16)
#define TC_is_ATTR_VERIFY(a)                  TC_m_ATTR_TST(a, 16)
#define TC_set_ATTR_TRUSTED(a)                TC_m_ATTR_SET(a, 17)
#define TC_raz_ATTR_TRUSTED(a)                TC_m_ATTR_RAZ(a, 17)
#define TC_is_ATTR_TRUSTED(a)                 TC_m_ATTR_TST(a, 17)
#define TC_set_ATTR_WRAP_WITH_TRUSTED(a)      TC_m_ATTR_SET(a, 18)
#define TC_raz_ATTR_WRAP_WITH_TRUSTED(a)      TC_m_ATTR_RAZ(a, 18)
#define TC_is_ATTR_WRAP_WITH_TRUSTED(a)       TC_m_ATTR_TST(a, 18)
#define TC_set_ATTR_ALWAYS_AUTHENTICATE(a)    TC_m_ATTR_SET(a, 19)
#define TC_raz_ATTR_ALWAYS_AUTHENTICATE(a)    TC_m_ATTR_RAZ(a, 19)
#define TC_is_ATTR_ALWAYS_AUTHENTICATE(a)     TC_m_ATTR_TST(a, 19)

#define TC_set_ATTR_CREATING(a)               TC_m_ATTR_SET(a, 31)
#define TC_raz_ATTR_CREATING(a)               TC_m_ATTR_RAZ(a, 31)
#define TC_is_ATTR_CREATING(a)                TC_m_ATTR_TST(a, 31)
#define TC_set_ATTR_AUTHENTICATE(a)           TC_m_ATTR_SET(a, 30)
#define TC_raz_ATTR_AUTHENTICATE(a)           TC_m_ATTR_RAZ(a, 30)
#define TC_is_ATTR_AUTHENTICATE(a)            TC_m_ATTR_TST(a, 30)
/************************************************************ 
       Flags des attributs presents
*************************************************************/
#define TC_HERE_BOOLEEN          0x80000000
#define TC_HERE_LABEL            0x40000000
#define TC_HERE_SUBJECT          0x20000000
#define TC_HERE_ID               0x10000000
#define TC_HERE_ISSUER           0x08000000
#define TC_HERE_SERIAL_NUMBER    0x04000000
#define TC_HERE_VALUE            0x02000000
#define TC_HERE_VALUE_PART       0x01000000
#define TC_HERE_MODULUS_BITS     0x00800000
#define TC_HERE_PUBLIC_EXPONENT  0x00400000
#define TC_HERE_START_DATE       0x00200000
#define TC_HERE_END_DATE         0x00100000
#define TC_HERE_MODULUS          0x00080000
#define TC_HERE_PRIVATE_EXPONENT 0x00040000
#define TC_HERE_EXPONENT_1       0x00020000
#define TC_HERE_EXPONENT_2       0x00010000
#define TC_HERE_PRIME_1          0x00008000
#define TC_HERE_PRIME_2          0x00004000
#define TC_HERE_COEFFICIENT      0x00002000
#define TC_HERE_APPLICATION      0x00001000
#define TC_HERE_OBJECT_ID        0x00000800

// PCA4_ECC
#define TC_HERE_ECC_CURVE        0x00800000
#define TC_HERE_ECC_PUB          0x00400000
/******************************************* 
        Commandes de hachage
********************************************/
#define TC_HASH_KLEN_MASK								0xF0
#define TC_HASH_WITHOUT_CONTEXT                         (char)0x0   // 0000
#define TC_HASH_WITH_CONTEXT_SAVE                       (char)0x5   // 0101
#define TC_HASH_WITH_CONTEXT_LOAD                       (char)0x6   // 0110
#define TC_HASH_WITH_CONTEXT_LOAD_AND_SAVE              (char)0x7   // 0111
#define TC_HASH_WITH_KEY_HMAC                           (char)0x8   // 1000
#define TC_HASH_WITH_KEY_AND_CONTEXT_SAVE_HMAC_FIRST    (char)0x9   // 1001
#define TC_HASH_WITH_KEY_AND_CONTEXT_LOAD_HMAC_LAST     (char)0xa   // 1010

#define TC_HASH_WITH_KEY_MASK                           (char)0x8   // Masque indiquant si l'operation est un HMAC
#define TC_HASH_CONTEXT_MASK                            (char)0x1   // Masque indiquant si le resultat est un contexte
#define TC_HASH_CONTEXT_LOAD_MASK                       (char)0x2   // Masque indiquant si un contexte est charge

#define TC_HASH_CTX_BYTE_LENGTH                         28    //octets

#define TC_HASH_SHA256                                 TC_HASH_WITHOUT_CONTEXT
#define TC_HMAC_SHA256                                 TC_HASH_WITH_KEY_HMAC

#define TC_SHA512_MASK_MBZ							   0xFFFE00F0
#define TC_HASH_512_KLEN_MASK						   0xFF00
#define TC_SHA_MODE_384                                1  // A ajouterdans le champ pad[1] a tout code commande concernant SHA384
#define TC_HASH_SHA384                                 TC_HASH_WITHOUT_CONTEXT
#define TC_HMAC_SHA384                                 TC_HASH_WITH_KEY_HMAC
#define TC_HASH_SHA512                                 TC_HASH_WITHOUT_CONTEXT
#define TC_HMAC_SHA512                                 TC_HASH_WITH_KEY_HMAC

#define TC_HASH256_CTX_BYTE_LENGTH                     40    //octets
#define TC_HASH384_CTX_BYTE_LENGTH                     72    //octets
#define TC_HASH512_CTX_BYTE_LENGTH                     72    //octets

/******************************************* 
        Commandes de chiffrement
********************************************/
#define TC_TWO_KEYS_MODE_MASK                           (char)0x40 // 01000000
#define TC_CBC_MASK                                     (char)0x30 // 00110000
#define TC_ENCRYPT_DECRYPT_MASK                         (char)0x4  // 00000100
#define TC_SIGN_VERIFY_MASK		                        (char)0x3  // 00000011

#define TC_AES_MASK_MBZ									0xC8       // 01001000
#define TC_AES_SIGN		                                1
#define TC_AES_VERIFY	                                2
#define TC_AES_ENCRYPT                                  0
#define TC_AES_DECRYPT                                  4
#define TC_AES_CBC                                      (3 << 4)
#define TC_AES_ECB                                      0
#define TC_AES_KEY_1                                    0
#define TC_AES_KEY_2                                    (1 << 6)
#define TC_AES_128										(1 << 7)

/*********************************************
PCA4_NEW
Interface automate DES  (TC_CRYPTO_DES) DES3 ou DES
**********************************************/
#define TC_DES_MASK_MBZ									0xE0       // 11100000
#define TC_DES_SIGN		                                0x10	   // 00010000
#define TC_DES_VERIFY	                                8          // 00001000
#define TC_DES_CBC                                      4          // 00000100
#define TC_DES_ECB                                      0
#define TC_DES3_ENCRYPT                                 2		   // 00000010
#define TC_DES3_DECRYPT                                 3		   // 00000011
#define TC_DES_ENCRYPT                                  0          // 00000000
#define TC_DES_DECRYPT                                  1          // 00000001
#define TC_DES3_MASK                                    2          // 00000010

/******************************************* 
        Types d'objet PKCS11 sur un short
********************************************/
#define  TC_CERT_TYPE_X509                (short)0x0000
#define  TC_KEY_TYPE_RSA                  (short)0x0000
#define  TC_KEY_TYPE_ECC                  (short)0x0003
#define  TC_KEY_TYPE_GENERIC_SECRET       (short)0x0010
#define  TC_KEY_TYPE_DES                  (short)0x0013
#define  TC_KEY_TYPE_DES2                 (short)0x0014
#define  TC_KEY_TYPE_DES3                 (short)0x0015
#define  TC_KEY_TYPE_AES                  (short)0x001F
#define  TC_KEY_TYPE_ECC_KCDSA            (short)0x102F       // PCA4_NEW

#define  TC_KEY_TYPE_INVALID              0xFFFFFFFF

/******************************************* 
        Classes d'objet PKCS11 sur un short
********************************************/
#define  TC_OBJ_CLASS_DATA                (short)0x0000
#define  TC_OBJ_CLASS_CERT                (short)0x0001
#define  TC_OBJ_CLASS_PUB_KEY             (short)0x0002
#define  TC_OBJ_CLASS_PRIV_KEY            (short)0x0003
#define  TC_OBJ_CLASS_SECRET_KEY          (short)0x0004

/* valeur du champ status de transfert */
#define TC_A_SUIVRE                           0 /**< valeur du champ status : transfert en cours */
#define TC_FIN                                1 /**< valeur du champ status : transfert termine  */
#define TC_DEBUT                              2 /**< valeur du champ status : transfert demarre  */

#define TC_CONTEXT_LENGTH                     96

/*******************************************************************************
PCA4_NEW
Nouveaux attributs CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_WRAP_WITH_TRUSTED
CKA_KEY_GEN_MECHANISM, CKA_ALLOWED_MECHANISMS
attributs CKA_END_DATE et CKA_START_DATE ne sont plus incorpores aux attributs
dont la longueur max est configurable (label, ID, subject)
C_GenerateKeyPair RSA : possibilite de passer un exposant public de longueur quelconque
==> structure TC_t_GenerateKeyPair_template a la suite des 2 templates pour cles publique et privee
Pour ECC parametres du domaine suit les 2 templates 
********************************************************************************/
/** structure d'en-tete des attributs d'un objet (cle/certificat) */
typedef struct objectPkcs11AttributesHeader
{
  short object_class;                         /**< classe de l'objet                                    */
  short type;                                 /**< type de la cle                                       */
  int   attributes[4];                        /**< TOKEN, PRIVATE, MODIFIABLE, etc.                     */
  char  start_date[8];
  char  end_date[8];
  int   gen_mechanism;
  unsigned int   mechanisms_len;
  int   mechanisms[8];
  unsigned int   varAttrsLen;				// Longueur container ((wrap/unwrap templates) + container (label + ID + (subject)))
  unsigned int   wrapTemplate_len;           // 0 pour cles privees
  unsigned int   unwrapTemplate_len;         // 0 pour cles publiques
  int   rfu[2];
} TC_t_objectPkcs11AttributesHeader;

typedef struct objectAttributesTail
{
  int   rfu;
  int   valueLen;       // modulusBits pour cle RSA, longueur p pour cle ECC
} TC_t_objectAttributesTail;

/*****************************************************************		
PCA4_NEW structure du message pour une requete TC_GenerateKeyPair
******************************************************************/
typedef struct GenerateKeyPair_template
{
  int   rfu;
  unsigned int  modulusBits;
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  /* modulus */
  char publicExponent[MAX_RSA_MODULUS_LEN];
} TC_t_GenerateKeyPair_template;

typedef struct GenerateEccKeyPair_template
{
  int   rfu;
  unsigned int   keyLen;
  ECC_t_curve_ref  curve;
  ECC_t_public_key pub;
} TC_t_GenerateEccKeyPair_template;

/** structure du message pour une requete TC_GenerateKey       */
typedef struct GenerateKey_template
{
  int   rfu;
  unsigned int   valueLen;           // pas toujours significatif
} TC_t_GenerateKey_template;

typedef struct GenerateKeyPair_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                    */
  char  data[TC_DATA_LEN];          /**< partie data
									// PCA4_NEW + TC_t_GenerateKeyPair_template en RSA, + ECC_t_curve_ref en ECC                                                                   */
} TC_t_GenerateKeyPair_msg;


/** structure des donnees de la reponse pour une requete TC_GenerateKeyPair       */
typedef struct GenerateKeyPair_rsp
{
  int   privateObjectHandle;        /**< handle de l'objet prive                                                          */
  int   publicObjectHandle;         /**< handle de l'objet public                                                         */
  char  modulus[TC_DATA_LEN];       /**< Modulus                                                         */
} TC_t_GenerateKeyPair_rsp;

/** structure du message pour une requete TC_GenerateBigKeyPair      */
typedef struct GenKeyPairBigObject_msg
{
  short           slotId;                 /**< identifiant du slot virtuel   */
  short           functionId;             /**< identifiant de la fonction    */
  unsigned short  pubClass;               /**< Classe de la cle publique     */
  unsigned short  pubType;                /**< Type de la cle publique       */
  unsigned int    presentPubAttrFlags;    /**< Flags des attributs presents  */
  unsigned short  privClass;              /**< Classe de la cle privee       */
  unsigned short  privType;               /**< Type de la cle privee         */
  unsigned int    presentPrivAttrFlags;   /**< Flags des attributs presents  */
  char            data[TC_DATA_LEN];      /**< partie data                   */
} TC_t_GenKeyPairBigObject_msg;

/** structure du message pour une requete TC_GenerateKey       */
typedef struct GenerateKey_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
  char  keyAttributes[TC_DATA_LEN]; /**< structure des attributs d'une cle secrete                                    */
} TC_t_GenerateKey_msg;

/** structure du message pour une requete TC_Generate_master_secret      */
typedef struct GenerateMS_msg
{
  short slotId;       				/**< identifiant du slot virtuel        */
  short functionId;   				/**< identifiant de la fonction         */
  int   objectHandle;           	/**< handle du pre-master-secret  */
  int 	client_random_len;
  int 	server_random_len;
  char 	client_random[TC_SSL_MAX_CLIENT_RANDOM_LEN];
  char 	server_random[TC_SSL_MAX_SERVER_RANDOM_LEN];
  char  keyAttributes[TC_DATA_LEN]; /**< structure des attributs d'une cle secrete */
} TC_t_GenerateMS_msg;

/** structure du message pour une requete TC_Generate_master_secret      */
typedef struct DeriveMS_msg
{
  short slotId;       				/**< identifiant du slot virtuel        */
  short functionId;   				/**< identifiant de la fonction         */
  int   objectHandle;           	/**< handle du pre-master-secret  */
  int 	mac_size;
  int 	key_size;
  int 	iv_size;
  int 	client_random_len;
  int 	server_random_len;
  char 	client_random[TC_SSL_MAX_CLIENT_RANDOM_LEN];
  char 	server_random[TC_SSL_MAX_SERVER_RANDOM_LEN];
  char  keyAttributes[TC_DATA_LEN]; /**< structure des attributs d'une cle secrete */
} TC_t_DeriveMS_msg;


/** structure des donnees de la reponse pour une requete TC_GenerateKey       */
typedef struct GenerateKey_rsp
{
  int   objectHandle;               /**< handle de l'objet genere         */
} TC_t_GenerateKey_rsp;

/** structure des donnees de la reponse pour une requete C_Generate_master_secret  */
typedef struct GenerateMS_rsp
{
  int   objectHandle;               /**< handle de l'objet genere                  */
  int   SSL_Version;                /**< client SSL version number                 */
} TC_t_GenerateMS_rsp;

/** structure des donnees de la reponse pour une requete C_Derive_master_secre     */
typedef struct DeriveMS_rsp
{
  int cl_mac_handle;
  int sv_mac_handle;
  int cl_key_handle;
  int sv_key_handle;
  int SSL_Version;                /**< client SSL version number       */
  char cl_iv[TC_SSL_MAX_IV_LEN];
  char sv_iv[TC_SSL_MAX_IV_LEN];
} TC_t_DeriveMS_rsp;

/** structure des objets token transferes pour les requetes TC_GetBeginTokenObjects et TC_GetNextTokenObjects    */
typedef struct TokenObject
{
  int   objectHandle;                   /**< handle de l'objet dans le token     */
  char  objectAttributes[TC_DATA_LEN];  /**< structure des attributs de l'objet  */
} TC_t_TokenObject;

/** Structure des parametres des mecanismes RSA PKCS OAEP   */
typedef struct RSA_PKCS_OAEP_Mechanism
{
  unsigned int   hashMechanism;
  unsigned int   MGF_Type;
  unsigned int   OAEP_SourceType;
  unsigned int   sourceDataLength;
  char  sourceData[64];   // jusqu'a un digest de SHA512
} TC_t_RSA_PKCS_OAEP_Mechanism;

/** Structure des parametres des mecanismes RSA PKCS PSS   */
typedef struct RSA_PKCS_PSS_Mechanism
{
  unsigned int   hashMechanism;
  unsigned int   MGF_Type;
  unsigned int   saltLength;
} TC_t_RSA_PKCS_PSS_Mechanism;

//----------------------------------------------------------------------
/** structure des messages constitues par la lib              */
//----------------------------------------------------------------------

/** structure du message pour une requete TC_CreateObject      */
typedef struct CreateObject_msg
{
  short slotId;                 /**< identifiant du slot virtuel   */
  short functionId;             /**< identifiant de la fonction    */
  char  data[TC_DATA_LEN];      /**< partie data                   */
} TC_t_CreateObject_msg;


/** structure du message pour une requete TC_CreateBigObject      */
typedef struct CreateBigObject_msg
{
  short           slotId;                 /**< identifiant du slot virtuel   */
  short           functionId;             /**< identifiant de la fonction    */
  unsigned short  objectClass;            /**< Classe de l'objet             */
  unsigned short  objectType;             /**< Type de l'objet               */
  unsigned int    presentAttrFlags;       /**< Flags des attributs presents  */
  char            data[TC_DATA_LEN];      /**< partie data                   */
} TC_t_CreateBigObject_msg;

/** structure du message pour une requete TC_CopyObject      */
typedef struct CopyObject_msg
{
  short           slotId;                 /**< identifiant du slot virtuel   */
  short           functionId;             /**< identifiant de la fonction    */
  int             objectHandle;           /**< handle de l'objet a copier    */
  unsigned int    presentAttrFlags;       /**< Flags des attributs presents  */
  char            data[TC_DATA_LEN];      /**< partie data                   */
} TC_t_CopyObject_msg;

/** structure du message pour une requete TC_Dump      */
typedef struct Dump_msg
{
  short           slotId;                 /**< identifiant du slot virtuel   */
  short           functionId;             /**< identifiant de la fonction    */
  unsigned int   wordSize;               /**< taille d'un mot               */
  unsigned int   count;                  /**< nombre de mots a dumper       */
  void            *addr;                  /**< adresse debut du dump         */
} TC_t_Dump_msg;


/** structure du message pour une requete TC_DestroyObject       */
typedef struct DestroyVarParam
{
  int   objectHandle;           /**< handle de l'objet a detruire  */
} TC_t_DestroyVarParam;

typedef struct DestroyObject_msg
{
  short                 slotId;      /**< identifiant du slot virtuel        */
  short                 functionId;  /**< identifiant de la fonction         */
  TC_t_DestroyVarParam  var;         /**< parametres de la partie variable   */
} TC_t_DestroyObject_msg;


/** structure du message pour une requete TC_GetSensitiveAttributes       */
typedef struct GetSensAttrVarParam
{
  unsigned int   objectHandle;           /**< handle de l'objet pour lequel les attributs sont demandes */
} TC_t_GetSensAttrVarParam;

typedef struct GetSensitiveAttributes_msg
{
  short                     slotId;     /**< identifiant du slot virtuel       */
  short                     functionId; /**< identifiant de la fonction        */
  TC_t_GetSensAttrVarParam  var;        /**< parametres de la partie variable  */
} TC_t_GetSensitiveAttributes_msg;

/** structure du message pour une requete TC_GetBigSensitiveAttributes       */
typedef struct GetBigSensAttrVarParam
{
  unsigned int   objectHandle;           /**< handle de l'objet pour lequel les attributs sont demandes  */
  unsigned int   length;                 /**< Longueur en octet de la partie d'attribut demande          */
  unsigned int   offset;                 /**< Offset en octet de la partie d'attribut demande            */
} TC_t_GetBigSensAttrVarParam;

typedef struct GetBigSensitiveAttributes_msg
{
  short                     slotId;     /**< identifiant du slot virtuel       */
  short                     functionId; /**< identifiant de la fonction        */
  TC_t_GetBigSensAttrVarParam  var;     /**< parametres de la partie variable  */
} TC_t_GetBigSensitiveAttributes_msg;


/** structure des donnees du message pour une reponse a une requete TC_GetSensitiveAttributes       */
typedef struct GetSensitiveAttributes_rsp
{
  char  keyAttributes[TC_DATA_LEN]; /**< structure des attributs pkcs#11 sensibles de la cle                          */
} TC_t_GetSensitiveAttributes_rsp;


/** structure du message pour une requete TC_SetAttributeValue       */
typedef struct SetAttrVarParam
{
  unsigned int   objectHandle;               /**< handle de l'objet pour lequel les attributs sont modifies                    */
} TC_t_SetAttrVarParam;

typedef struct SetAttributeValue_msg
{
  short                     slotId;      /**< identifiant du slot virtuel       */
  short                     functionId;  /**< identifiant de la fonction        */
  TC_t_SetAttrVarParam  var;             /**< parametres de la partie variable  */
  char  attributes[TC_DATA_LEN];         /**< structure des attributs           */
} TC_t_SetAttributeValue_msg;


/** structure du message pour une requete TC_SetBigObjectAttributes      */
typedef struct SetBigObjectAttributes_msg
{
  short         slotId;                 /**< identifiant du slot virtuel   */
  short         functionId;             /**< identifiant de la fonction    */
  unsigned int  objectHandle;           /**< handle de l'objet pour lequel les attributs sont modifies */
  unsigned int  presentAttrFlags;       /**< Flags des attributs presents  */
  char          data[TC_DATA_LEN];      /**< attributes (partie data)      */
} TC_t_SetBigObjectAttributes_msg;

/** structure du message pour une requete TC_SetBigObjectAttributes      */
typedef struct GetAttributes_msg
{
  short         slotId;                 /**< identifiant du slot virtuel   */
  short         functionId;             /**< identifiant de la fonction    */
  int           objectHandle;           /**< handle de l'objet pour lequel les attributs sont demandes                    */
  int           offset;                 /**< offset en octet dans les attributs  */
} TC_t_GetAttributes_msg;

/** structure du message pour une requete TC_Crypto_AES       */
typedef struct Crypto_AESVarParam
{
  char  pad1[3];                /**< padding a 0                                                                      */
  char  aes_Cmd;                /**< detail de la commande AES                                                        */
  unsigned int   dataLength;             /**< longueur en octets des donnees a chiffrer                                        */
  int   dataOffsetIn;           /**< l'offset en octets du debut des donnees a chiffrer en entree dans la zone data   */
  int   dataOffsetOut;          /**< l'offset en octets du debut des donnees où sera retourne le chiffrement          */
  unsigned int   keyHandle1;             /**< handle de la 1ere cle requise pour traiter la commande                           */
  int   keyHandle2;             /**< handle de la 2eme cle requise pour traiter la commande                           */
  int   ivAddress;              /**< egal a 0                                                                         */ 
  char  iv[16];                 /**< IV                                             */
} TC_t_Crypto_AESVarParam;

typedef struct Crypto_AES_msg
{
  short                    slotId;            /**< identifiant du slot virtuel       */
  short                    functionId;        /**< identifiant de la fonction        */
  TC_t_Crypto_AESVarParam  var;               /**< parametres de la partie variable  */
  char                     data[TC_DATA_LEN]; /**< partie data                       */
} TC_t_Crypto_AES_msg;

#define AES_ENCRYPT_DATA_AREA_OFFSET          48

/** structure de l'en-tete du message pour une requete TC_Crypto_SHA       */
typedef struct Crypto_SHAVarParam
{
  char  pad1[2];                    /**< padding a 0                                                                      */
  unsigned char  keyLength;                  /**< taille de la cle de HMAC-SHA en multiples de 32 bits                             */
  char  sha_Cmd;                    /**< detail de la commande SHA                                                        */
  unsigned int   dataLength;                 /**< longueur en octets des donnees a hacher ou a signer                              */
  int   dataOffsetIn;               /**< l'offset en octets du debut des donnees a signer en entree dans la zone data     */
  int   dataOffsetOut;              /**< egal a 0                                                                         */ 
  unsigned int   keyHandle;                  /**< l'adresse de la cle requise pour traiter la commande de HMAC-SHA                 */
  int   contextAddress;             /**< egal a 0                                                                         */ 
  char  context[TC_CONTEXT_LENGTH]; /**< contexte                                                                         */
} TC_t_Crypto_SHAVarParam;

typedef struct Crypto_SHA_msg
{
  short                    slotId;            /**< identifiant du slot virtuel       */
  short                    functionId;        /**< identifiant de la fonction        */
  TC_t_Crypto_SHAVarParam  var;               /**< parametres de la partie variable  */
  char                     data[TC_DATA_LEN]; /**< partie data                       */
} TC_t_Crypto_SHA_msg;

#define SHA_CONTEXT_OFFSET      28
#define SHA_DATA_OFFSET         (SHA_CONTEXT_OFFSET + TC_CONTEXT_LENGTH)  // Au dela (en depassant) du debut des donnees

/*******************************************************************************
PCA4_NEW
DES3 ==> DES en general (DES ou DES3)
********************************************************************************/
/** structure du message pour une requete TC_Crypto_DES3       */
typedef struct Crypto_DES3VarParam
{
  char  pad1[3];                /**< padding a 0                                                                      */
  char  des3_Cmd;               /**< detail de la commande DES3                                                       */
  unsigned int   dataLength;             /**< longueur en octets des donnees a chiffrer                                        */
  int   dataOffsetIn;           /**< l'offset en octets du debut des donnees a chiffrer en entree dans la zone data   */
  int   dataOffsetOut;          /**< l'offset en octets du debut des donnees où sera retourne le chiffrement          */
  unsigned int   keyHandle1;             /**< handle de la 1ere cle requise pour traiter la commande                           */
  int   keyHandle2;             /**< handle de la 1ere cle requise pour traiter la commande                           */
  int   ivAddress;              /**< egal a 0                                                                         */ 
  char  iv[8];                  /**< IV                                              */
} TC_t_Crypto_DES3VarParam;

#define DES_ENCRYPT_DATA_AREA_OFFSET          40

typedef struct Crypto_DES3_msg
{
  short                     slotId;            /**< identifiant du slot virtuel       */
  short                     functionId;        /**< identifiant de la fonction        */
  TC_t_Crypto_DES3VarParam  var;               /**< parametres de la partie variable  */
  char                      data[TC_DATA_LEN]; /**< partie data                       */
} TC_t_Crypto_DES3_msg;


/** structure du message pour une requete TC_Crypto_MD5       */
typedef struct Crypto_MD5VarParam
{
  char  pad1[2];                    /**< padding a 0                                                                      */
  char  keyLength;                  /**< taille de la cle de HMAC-MD5 en multiples de 32 bits                             */
  char  md5_Cmd;                    /**< detail de la commande MD5                                                        */
  unsigned int   dataLength;                 /**< longueur en octets des donnees a hacher ou a signer                              */
  int   dataOffsetIn;               /**< l'offset en octets du debut des donnees a signer en entree dans la zone data     */
  int   dataOffsetOut;              /**< egal a 0                                                                         */ 
  unsigned int   keyHandle;                  /**< l'adresse de la cle requise pour traiter la commande de HMAC-MD5                 */
  int   contextAddress;             /**< egal a 0                                                                         */ 
  char  context[TC_CONTEXT_LENGTH]; /**< contexte                                                                         */
} TC_t_Crypto_MD5VarParam;

typedef struct Crypto_MD5_msg
{
  short                    slotId;            /**< identifiant du slot virtuel       */
  short                    functionId;        /**< identifiant de la fonction        */
  TC_t_Crypto_MD5VarParam  var;               /**< parametres de la partie variable  */
  char                     data[TC_DATA_LEN]; /**< partie data                       */
} TC_t_Crypto_MD5_msg;


/** structure du message pour une requete TC_Encrypt       */
typedef struct EncryptVarParam
{
  unsigned int   mechanismType;             /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_X509)   */
  unsigned int   keyHandle;                 /**< le handle de la cle de chiffrement                                       */
  unsigned int   mechanismParametersLength; /**< longueur des parametres du mechanisme                                    */
} TC_t_EncryptVarParam;

typedef struct Encrypt_msg
{
  short                 slotId;                           /**< identifiant du slot virtuel       */
  short                 functionId;                       /**< identifiant de la fonction        */
  TC_t_EncryptVarParam  var;                              /**< parametres de la partie variable  */
  char                  mechanismParameters[TC_DATA_LEN]; /**< parametres du mecanisme           */
} TC_t_Encrypt_msg;


/** structure du message pour une requete TC_Decrypt       */
typedef struct DecryptVarParam
{
  unsigned int   mechanismType;             /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_X509)   */
  unsigned int   keyHandle;                 /**< le handle de la cle de chiffrement                                       */
  unsigned int   mechanismParametersLength; /**< longueur des parametres du mechanisme                                    */
} TC_t_DecryptVarParam;

typedef struct Decrypt_msg
{
  short                 slotId;                           /**< identifiant du slot virtuel       */
  short                 functionId;                       /**< identifiant de la fonction        */
  TC_t_DecryptVarParam  var;                              /**< parametres de la partie variable  */
  char                  mechanismParameters[TC_DATA_LEN]; /**< parametres du mecanisme           */
} TC_t_Decrypt_msg;


// PCA4_NEW SIGNATURE ECKCDSA (mecanisme proprietaire CKM_ECKCDSA)
// Avant de calculer (ou de verifier) une signature ECKCSA 
// Il faut d'abord hasher l'ensemble signId + reference de courbe (structure CK_ECKCDSA_PARAMS) + cle plublique, soit H1 le resultat obtenu
// puis hasher H1 + donnees
// Cette fonction multi hash est realisee par la PCA4 en plusieurs requetes(TC_SIGN_INIT_ECKCDSA pour calcul de H1, puis 1 ou plusieurs TC_CRYPTO_SHA)
// Elle produit le hash final qui doit etre repasse en tant que donnees a signer dans la requete TC_SIGN (ou TC_VERIFY) qui va suivre

/** structure du message pour une requete sign/verify init ECKCDSA */
typedef struct SignEckcdsaVarParam
{
  int   mechanismType;    /**< type de mecanisme == CKM_ECKCDSA ou CKM_SOFTWARE_SIGN*/
  unsigned int   keyHandle;       // le handle de la cle de signature (privee pour signer, publique pour verifier)                                                        */
  unsigned int hashAlg; // mecanisme de hash a utiliser pour CertData + donnees
  unsigned int ulSignId;
} TC_t_SignEckcdsaVarParam;

typedef struct SignEckcdsa_msg
{
  short              slotId;               /**< identifiant du slot virtuel       */
  short              functionId;           /**< identifiant de la fonction        */
  TC_t_SignEckcdsaVarParam  var;           /**< parametres de la partie variable  */
  char               signId[TC_DATA_LEN]; 
} TC_t_SignEckcdsa_msg;

/** structure du message pour une requete TC_Sign       */
typedef struct SignVarParam
{
  int   mechanismType;              /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_X509) */
  int   keyHandle;                  /**< le handle de la cle de signature                                                         */
  int   mechanismParametersLength;  /**< longueur des parametres du mechanisme                                                    */
} TC_t_SignVarParam;

typedef struct Sign_msg
{
  short              slotId;                           /**< identifiant du slot virtuel       */
  short              functionId;                       /**< identifiant de la fonction        */
  TC_t_SignVarParam  var;                              /**< parametres de la partie variable  */
  char               mechanismParameters[TC_DATA_LEN]; /**< parametres du mecanisme           */
} TC_t_Sign_msg;


/** structure du message pour une requete TC_Verify       */
typedef struct VerifyVarParam
{
  unsigned int   mechanismType;             /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_X509) */
  unsigned int   keyHandle;                 /**< le handle de la cle de signature                                                         */
  unsigned int   signatureLength;           /**< la longueur en octets de la signature                                                         */
  unsigned int   mechanismParametersLength; /**< longueur des parametres du mechanisme                                                    */
} TC_t_VerifyVarParam;

typedef struct Verify_msg
{
  short                slotId;                           /**< identifiant du slot virtuel       */
  short                functionId;                       /**< identifiant de la fonction        */
  TC_t_VerifyVarParam  var;                              /**< parametres de la partie variable  */
  char                 mechanismParameters[TC_DATA_LEN]; /**< parametres du mecanisme           */
} TC_t_Verify_msg;

/** structure du message pour une requete TC_WrapKey en PKCS     */
typedef struct WrapPKCSVarParam
{
  int   mechanismType;                                /**< type de mecanisme (CKM_RSA_PKCS)           */
  int   handleWrappingKey;                            /**< le handle de la cle "wrappante"            */
  int   keyHandle;                                    /**< le handle de la cle "a wrapper"            */
  int   mechanismParametersLength;                    /**< longueur des parametres du mecanisme (0)   */
} TC_t_WrapPKCSVarParam;

typedef struct WrapKeyPKCS_msg
{
  short                  slotId;      /**< identifiant du slot virtuel       */
  short                  functionId;  /**< identifiant de la fonction        */
  TC_t_WrapPKCSVarParam  var;         /**< parametres de la partie variable  */
} TC_t_WrapKeyPKCS_msg;

/** structure du message pour une requete TC_WrapKey en SaveKey     */
typedef struct WrapSaveKeyVarParam
{
  unsigned int   mechanismType;                                /**< type de mecanisme (CKM_SAVE_RESTORE_KEY)   */
  unsigned int   handleWrappingKey;                            /**< MBZ            */
  unsigned int   keyHandle;                                    /**< le handle de la cle "a wrapper"            */
  unsigned int   mechanismParametersLength;                    /**< MBZ       */
  unsigned int   resultLength;                                 /**< longueur de la cle sauvee                  */
} TC_t_WrapSaveKeyVarParam;

typedef struct WrapSaveKey_msg
{
  short                     slotId;      /**< identifiant du slot virtuel       */
  short                     functionId;  /**< identifiant de la fonction        */
  TC_t_WrapSaveKeyVarParam  var;         /**< parametres de la partie variable  */
} TC_t_WrapSaveKey_msg;


/** structure du message pour une requete TC_WrapKey en OAEP     */
typedef struct WrapOAEPVarParam
{
  unsigned int   mechanismType;                                /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,  CKM_RSA_PKCS_X509, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)     */
  unsigned int   handleWrappingKey;                            /**< le handle de la cle "wrappante"                                                                                                                                      */
  unsigned int   keyHandle;                                    /**< le handle de la cle "a wrapper"                                                                                                                                      */
  unsigned int   mechanismParametersLength;                    /**< longueur des parametres du mecanisme OAEP                                                                                                                            */
  TC_t_RSA_PKCS_OAEP_Mechanism mechanismParameters;   /**< parametres OAEP                                                                                                                                                      */
} TC_t_WrapOAEPVarParam;

typedef struct WrapKeyOAEP_msg
{
  short                  slotId;      /**< identifiant du slot virtuel       */
  short                  functionId;  /**< identifiant de la fonction        */
  TC_t_WrapOAEPVarParam  var;         /**< parametres de la partie variable  */
} TC_t_WrapKeyOAEP_msg;


/** structure du message pour une requete TC_WrapKey en DES3     */
typedef struct WrapDES3VarParam
{
  int   mechanismType;          /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,  CKM_RSA_PKCS_X509, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)     */
  int   handleWrappingKey;      /**< le handle de la cle "wrappante"                                                                                                                                      */
  int   keyHandle;              /**< le handle de la cle "a wrapper"                                                                                                                                      */
  int   ivLength;               /**< longueur du vecteur initial                                                                                                                                          */
  char  iv[8];                  /**< IV (8 octets en DES3, et 16 octets en AES)                                                                                                                           */
} TC_t_WrapDES3VarParam;

typedef struct WrapKeyDES3_msg
{
  short                  slotId;      /**< identifiant du slot virtuel       */
  short                  functionId;  /**< identifiant de la fonction        */
  TC_t_WrapDES3VarParam  var;         /**< parametres de la partie variable  */
} TC_t_WrapKeyDES3_msg;


/** structure du message pour une requete TC_WrapKey en AES       */
typedef struct WrapAESVarParam
{
  unsigned int   mechanismType;          /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,  CKM_RSA_PKCS_X509, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)     */
  unsigned int   handleWrappingKey;      /**< le handle de la cle "wrappante"                                                                                                                                      */
  unsigned int   keyHandle;              /**< le handle de la cle "a wrapper"                                                                                                                                      */
  unsigned int   ivLength;               /**< longueur du vecteur initial                                                                                                                                          */
  char  iv[16];                 /**< IV (8 octets en DES3, et 16 octets en AES)                                                                                                                           */
} TC_t_WrapAESVarParam;

typedef struct WrapKeyAES_msg
{
  short                 slotId;      /**< identifiant du slot virtuel       */
  short                 functionId;  /**< identifiant de la fonction        */
  TC_t_WrapAESVarParam  var;         /**< parametres de la partie variable  */
} TC_t_WrapKeyAES_msg;

/** structure des donnees de la reponse pour une requete TC_WrapKey en OAEP  */
typedef struct WrapKeyOAEP_rsp
{
  char  data[TC_DATA_LEN];                            /**< cle "wrappee"                                                                    */
} TC_t_WrapKeyOAEP_rsp;


/** structure des donnees de la reponse pour une requete TC_WrapKey en DES3  */
typedef struct WrapKeyDES3_rsp
{
  int   mechanismType;          /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,  CKM_RSA_PKCS_X509, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)     */
  int   handleWrappingKey;      /**< le handle de la cle "wrappante"                                                                                                                                      */
  int   keyHandle;              /**< le handle de la cle "a wrapper"                                                                                                                                      */
  int   ivLength;               /**< longueur du vecteur initial                                                                                                                                          */
  char  iv[8];                  /**< IV (8 octets en DES3, et 16 octets en AES)                                                                                                                           */
  char  data[TC_DATA_LEN];      /**< cle "wrappee"                                                                    */
} TC_t_WrapKeyDES3_rsp;


/** structure des donnees de la reponse pour une requete TC_WrapKey en AES       */
typedef struct WrapKeyAES_rsp
{
  int   mechanismType;          /**< type de mecanisme (CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,  CKM_RSA_PKCS_X509, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)     */
  int   handleWrappingKey;      /**< le handle de la cle "wrappante"                                                                                                                                      */
  int   keyHandle;              /**< le handle de la cle "a wrapper"                                                                                                                                      */
  int   ivLength;               /**< longueur du vecteur initial                                                                                                                                          */
  char  iv[16];                 /**< IV (8 octets en DES3, et 16 octets en AES)                                                                                                                           */
  char  data[TC_DATA_LEN];      /**< cle "wrappee"                                                                    */
} TC_t_WrapKeyAES_rsp;


/** structure du message pour le debut de la requete TC_UnwrapKey  */
typedef struct UnwrapVarParam
{
  unsigned int   mechanismType;              /**< type de mecanisme (CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)    */
  unsigned int   wrappingKeyHandle;          /**< le handle de la cle "wrappante"                                                                                              */
  unsigned int   ivLength;                   /**< longueur du vecteur initial                                                    */
  char  iv[16];                     /**< vecteur initial                                                                */
} TC_t_UnwrapVarParam;

/** structure du message pour le debut de la requete TC_UnwrapKey en PKCS  */
typedef struct UnwrapPKCSVarParam
{
  int   mechanismType;                                /**< type de mecanisme (CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)    */
  int   wrappingKeyHandle;                            /**< le handle de la cle "wrappante"                                                                                              */
  int   mechanismParametersLength;                    /**< longueur des parametres du mecanisme OAEP                                                                                                                            */
} TC_t_UnwrapPKCSVarParam;

/** structure du message pour le debut de la requete TC_UnwrapKey en OAEP  */
typedef struct UnwrapOAEPVarParam
{
  unsigned int   mechanismType;                                /**< type de mecanisme (CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)    */
  unsigned int   wrappingKeyHandle;                            /**< le handle de la cle "wrappante"                                                                                              */
  unsigned int   mechanismParametersLength;                    /**< longueur des parametres du mecanisme OAEP                                                                                                                            */
  TC_t_RSA_PKCS_OAEP_Mechanism mechanismParameters;   /**< parametres OAEP                                                                                                                                                      */
} TC_t_UnwrapOAEPVarParam;

/** structure du message pour le debut de la requete TC_UnwrapKey en DES3  */
typedef struct UnwrapDES3VarParam
{
  int   mechanismType;              /**< type de mecanisme (CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)    */
  int   wrappingKeyHandle;          /**< le handle de la cle "wrappante"                                                                                              */
  int   ivLength;                   /**< longueur du vecteur initial                                                    */
  char  iv[8];                      /**< vecteur initial                                                                */
} TC_t_UnwrapDES3VarParam;

/** structure du message pour le debut de la requete TC_UnwrapKey en AES  */
typedef struct UnwrapAESVarParam
{
  int   mechanismType;              /**< type de mecanisme (CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD)    */
  int   wrappingKeyHandle;          /**< le handle de la cle "wrappante"                                                                                              */
  int   ivLength;                   /**< longueur du vecteur initial                                                    */
  char  iv[16];                     /**< vecteur initial                                                                */
} TC_t_UnwrapAESVarParam;

typedef struct UnwrapKey_msg
{
  short                   slotId;     /**< identifiant du slot virtuel       */
  short                   functionId; /**< identifiant de la fonction        */
  TC_t_UnwrapVarParam     var;        /**< parametres de la partie variable  */
} TC_t_UnwrapKey_msg;


typedef struct UnwrapKeyPKCS_msg
{
  short                   slotId;             /**< identifiant du slot virtuel       */
  short                   functionId;         /**< identifiant de la fonction        */
  TC_t_UnwrapPKCSVarParam var;                /**< parametres de la partie variable  */
  char                    data[TC_DATA_LEN];  /**< data                              */                                                                                                               
} TC_t_UnwrapKeyPKCS_msg;


typedef struct UnwrapKeyOAEP_msg
{
  short                   slotId;     /**< identifiant du slot virtuel       */
  short                   functionId; /**< identifiant de la fonction        */
  TC_t_UnwrapOAEPVarParam var;        /**< parametres de la partie variable  */
} TC_t_UnwrapKeyOAEP_msg;


typedef struct UnwrapKeyDES3_msg
{
  short                   slotId;     /**< identifiant du slot virtuel       */
  short                   functionId; /**< identifiant de la fonction        */
  TC_t_UnwrapDES3VarParam var;        /**< parametres de la partie variable  */
} TC_t_UnwrapKeyDES3_msg;


typedef struct UnwrapKeyAES_msg
{
  short                  slotId;     /**< identifiant du slot virtuel       */
  short                  functionId; /**< identifiant de la fonction        */
  TC_t_UnwrapAESVarParam var;        /**< parametres de la partie variable  */
} TC_t_UnwrapKeyAES_msg;

/** structure des donnees de la reponse pour une requete TC_UnwrapKey       */
typedef struct UnwrapKey_rsp
{
  int                     unwrappedKeyHandle;          /**< handle de la cle "dewrappee"                                                                                              */
  char                    attributes[TC_DATA_LEN];     /**< attributs de la cle "dewrappee"                                                            */
} TC_t_UnwrapKey_rsp;


/** structure du message pour une requete TC_GenerateRandom       */
typedef struct GenRandVarParam
{
  unsigned int   randomLength ;    /**< longueur en octets du nombre aleatoire a generer                             */
} TC_t_GenRandVarParam;


typedef struct GenerateRandom_msg
{
  short                 slotId;     /**< identifiant du slot virtuel       */
  short                 functionId; /**< identifiant de la fonction        */
  TC_t_GenRandVarParam  var;        /**< parametres de la partie variable  */
} TC_t_GenerateRandom_msg;


/** structure des donnees de la reponse pour une requete TC_GenerateRandom       */
typedef struct GenerateRandom_rsp
{
  char  data[TC_DATA_LEN];          /**< nombre aleatoire                                                             */
} TC_t_GenerateRandom_rsp;


/** structure du message pour une requete TC_GetTokenStatus       */
typedef struct GetTokenStatus_msg
{
  short slotId;                     /**< identifiant du slot virtuel  */
  short functionId;                 /**< identifiant de la fonction   */
} TC_t_GetTokenStatus_msg;


/** structure des donnees de la reponse pour une requete TC_GetTokenStatus       */
typedef struct GetTokenStatus_rsp
{
  TC_t_TokenStatus_4 tokenStatus;         /**< structure des informations du token */
} TC_t_GetTokenStatus_rsp;

/** structure du message pour une requete TC_GetTokenStatus avec version      */
typedef struct GetExtTokenStatus_msg
{
  short slotId;                     /**< identifiant du slot virtuel    */
  short functionId;                 /**< identifiant de la fonction     */
  int   tokenInfoVersion;           /**< version du tokenInfo          */
} TC_t_GetExtTokenStatus_msg;


/** structure des donnees de la reponse pour une requete TC_GetTokenStatus en version etendue   */
typedef struct GetExtTokenStatus_rsp
{
  TC_t_TokenStatus_4 tokenStatus;         /**< structure des informations du token  */
} TC_t_GetExtTokenStatus_rsp;

/** structure du message pour une requete TC_GetMechList       */
typedef struct GetMechList_msg
{
  short slotId;                     /**< identifiant du slot virtuel  */
  short functionId;                 /**< identifiant de la fonction   */
  unsigned int length;             /**< length for the response      */
} TC_t_GetMechList_msg;

/** structure des donnees de la reponse pour une requete TC_GetMechList       */
typedef struct GetMechList_rsp
{
  unsigned int   length;         /**< length in bytes of the following list  */
  unsigned int   firstMechanism;
} TC_t_GetMechList_rsp;

/** structure du message pour une requete TC_GetMechInfo       */
typedef struct GetMechInfo_msg
{
  short         slotId;           /**< identifiant du slot virtuel  */
  short         functionId;       /**< identifiant de la fonction   */
  unsigned int mechanismType;
} TC_t_GetMechInfo_msg;

/** structure des donnees de la reponse pour une requete TC_GetMechInfo       */
typedef struct GetMechInfo_rsp
{
  unsigned int    ulMinKeySize;
  unsigned int    ulMaxKeySize;
  unsigned int    flags;
} TC_t_GetMechInfo_rsp;


/** structure du message pour une requete TC_GetConfiguration       */
typedef struct GetConfiguration_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_GetConfiguration_msg;


/** structure des donnees de la reponse pour une requete TC_GetConfiguration       */
typedef struct GetConfiguration_rsp
{
  TC_t_TokenConfiguration_4 tokenConfiguration;      /**< configuration du token*/
} TC_t_GetConfiguration_rsp;


/** structure du message pour une requete TC_SetConfiguration       */
typedef struct SetConfiguration_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                               /**< identifiant de la fonction                                      */
  TC_t_TokenConfiguration_4 tokenConfiguration;      /**< configuration du token                                         */
} TC_t_SetConfiguration_msg;

/** structure du message pour une requete TC_GetBeginTokenObjects       */
typedef struct GetBeginTokenObjects_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_GetBeginTokenObjects_msg;


/** structure des donnees de la reponse pour une requete TC_GetBeginTokenObjects       */
typedef struct GetBeginTokenObjects_rsp
{
  unsigned short    objectOffset;             /**< debut des objets                         */
  unsigned short    status;                   /**< etat du transfert des objets token       */
  unsigned short    secretKeyLength;          /**< taille d'un objet cle secrete            */
  unsigned short    secretKeysNumber;         /**< nombre d'objets cle secrete a transferer */
  unsigned short    rsaKeyLength;             /**< taille d'un objet cle RSA                */
  unsigned short    rsaKeysNumber;            /**< nombre d'objets cle RSA a transferer     */
  unsigned short    eccKeyLength;             /**< taille d'un objet cle ECC                */
  unsigned short    eccKeysNumber;            /**< nombre d'objets cle ECC a transferer     */
  unsigned short    certificateLength;        /**< taille d'un objet certificat             */
  unsigned short    certificateNumber;        /**< nombre d'objets cle RSA a transferer     */
  unsigned short    dataObjLength;            /**< taille d'un objet data             */
  unsigned short    dataObjNumber;            /**< nombre d'objets cle RSA a transferer     */
  TC_t_TokenObject  tokenObject[TC_DATA_LEN]; /**< structure des objets token a transferer  */
} TC_t_GetBeginTokenObjects_rsp;
#define TC_GET_BEGIN_OBJ_RSP_HEAD_SZ  (12*sizeof(short))

/** structure du message pour une requete TC_GetNextTokenObjects       */
typedef struct GetNextTokenObjects_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_GetNextTokenObjects_msg;


/** structure des donnees de la reponse pour une requete TC_GetNextTokenObjects       */
typedef struct GetNextTokenObjects_rsp
{
  short             objectOffset;             /**< debut des objets                                                     */
  short             status;                   /**< etat du transfert des objets token                                   */
  TC_t_TokenObject  tokenObject[TC_DATA_LEN]; /**< structure des objets token a transferer                              */
} TC_t_GetNextTokenObjects_rsp;

/** structure du message pour une requete TC_GetDate       */
typedef struct GetDate_msg
{
  short                    slotId;      /**< identifiant du slot virtuel       */
  short                    functionId;  /**< identifiant de la fonction        */
} TC_t_GetDate_msg;

typedef struct GetDate_rsp
{
  int                      date;        /**< date au format unix               */
} TC_t_GetDate_rsp;


typedef struct SetProfil_msg
{
  short                    slotId;      /**< identifiant du slot virtuel       */
  short                    functionId;  /**< identifiant de la fonction        */
  char                     fileData[TC_DATA_LEN]; /**< donnees des fichiers (data et signature) */
} TC_t_SetProfil_msg;

/** structure du message pour une requete TC_SoftwareUpdateBegin       */
typedef struct SoftUpdBegVarParam
{
  unsigned int   VersionsDatLength;
  short VersionsDatVersion;
  unsigned int   softwareLength;
  short softwareVersion;
  unsigned int   fpgaConfigurationLength;
  short fpgaConfigurationVersion;
#ifdef PCA4_USB
  unsigned int   fpgaUsbConfigurationLength;
  short fpgaUsbConfigurationVersion;
#endif
} TC_t_SoftUpdBegVarParam;

typedef struct TC_t_SoftwareUpdateBegin_file {
  int       codeLen;   
  short     Version;   
} TC_t_SoftwareUpdateBegin_file;

// redefinition de la structure TC_t_SoftUpdBegVarParam
#ifdef PCA4_USB
#define PCA4_SEND_UPDATE_FILE_COUNT	4
#else
#define PCA4_SEND_UPDATE_FILE_COUNT	3
#endif
typedef struct SoftUpdBegVarParam2 {
  TC_t_SoftwareUpdateBegin_file   lenAndVer[PCA4_SEND_UPDATE_FILE_COUNT];
} TC_t_SoftUpdBegVarParam2;

typedef struct SoftwareUpdateBegin_msg
{
  short                    slotId;      /**< identifiant du slot virtuel       */
  short                    functionId;  /**< identifiant de la fonction        */
  TC_t_SoftUpdBegVarParam  var;         /**< parametres de la partie variable  */
} TC_t_SoftwareUpdateBegin_msg;


/** structure du message pour une requete TC_SoftwareUpdateNext       */
typedef struct SoftUpdNxtVarParam
{
  short fileType;                   /**< type de fichier en cours de transfert */
  short status;                     /**< etat du transfert                     */
} TC_t_SoftUpdNxtVarParam;

typedef struct SoftwareUpdateNext_msg
{
  short                    slotId;                /**< identifiant du slot virtuel               */
  short                    functionId;            /**< identifiant de la fonction                */
  TC_t_SoftUpdNxtVarParam  var;                   /**< parametres de la partie variable          */
  char                     fileData[TC_DATA_LEN]; /**< donnees du fichier identifie par fileType */
} TC_t_SoftwareUpdateNext_msg;

/** structure du message pour une requete TC_DesinstallToken       */
typedef struct DesinstallToken_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_DesinstallToken_msg;


/** structure du message pour une requete TC_DepersonalizeToken       */
typedef struct DepersonalizeToken_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_DepersonalizeToken_msg;


/** structure du message pour une requete TC_TestToken       */
typedef struct TestToken_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_TestToken_msg;


/** structure du message pour une requete TC_SecurityReport       */
typedef struct SecRepVarParam
{
  int   maxResponseLength;
} TC_t_SecRepVarParam;

typedef struct SecurityReport_msg
{
  short                slotId;     /**< identifiant du slot virtuel      */
  short                functionId; /**< identifiant de la fonction       */
  int                  firstEvtIdx;
  int                  n_events;
} TC_t_SecurityReport_msg;


/** structure des donnees de la reponse pour une requete TC_SecurityReport       */
typedef struct SecurityReport_rsp
{
  int   n_events;
  char  securityReport[1600];
  char  pad[2];                       /**< padding a 0                                                                */
  short status;                       /**< etat du transfert en cours                                                 */
} TC_t_SecurityReport_rsp;


/** structure du message pour une requete TC_GetLog       */
typedef struct GetLog_msg
{
  short slotId;                 /**< date  */
  short functionId;             /**< identifiant de la fonction   */
  int                  firstEvtIdx;
  int                  n_events;
} TC_t_GetLog_msg;

/** structure des donnees de la reponse pour une requete TC_Get_log       */
typedef struct GetLog_rsp
{
  int   n_events;
  char  log[800];  /**   (16 oct)*(50 logs) = 800 = taille max de la reponse */
} TC_t_GetLog_rsp;

/** structure du message pour une requete TC_SaveKey       */
typedef struct SaveKeyVarParam
{
  int   maxResponseLength;
} TC_t_SaveKeyVarParam;

typedef struct SaveKey_msg
{
  short                 slotId;     /**< identifiant du slot virtuel      */
  short                 functionId; /**< identifiant de la fonction       */
  TC_t_SaveKeyVarParam  var;        /**< parametres de la partie variable */
} TC_t_SaveKey_msg;


/** structure des donnees de la reponse pour une requete TC_SaveKey       */
typedef struct SaveKey_rsp
{
  char  pad[2];                     /**< padding a 0                                                                  */
  short status;                     /**< etat du transfert en cours                                                   */
  char  keySet[TC_DATA_LEN];        /**< jeu de cle                                                                   */
} TC_t_SaveKey_rsp;

/** structure du message pour une requete TC_SaveKeyNext       */
typedef struct SaveKeyNext_msg
{
  short slotId;                     /**< identifiant du slot virtuel              */
  short functionId;                 /**< identifiant de la fonction               */
  unsigned int   handleKey;         /**< handle de la cle en cours de sauvegarde  */
} TC_t_SaveKeyNext_msg;


/** structure des donnees de la reponse pour une requete TC_SaveKeyNext       */
typedef struct SaveKeyNext_rsp
{
  short             saveOffset;               /**< emplacement de la sauvegarde dans la reponse */
  short             status;                   /**< etat du transfert des objets token           */
  char              saveKey[TC_DATA_LEN];     /**< suite de la sauvegarde de cle                */
} TC_t_SaveKeyNext_rsp;

/** structure du message pour une requete TC_RestoreKey       */
typedef struct RestoreKey_msg
{
  short   slotId;              /**< identifiant du slot virtuel      */
  short   functionId;          /**< identifiant de la fonction       */
  unsigned int     wrappedKeyLen;       /**< Longueur de la sauvegarde        */
  char    saveKey[TC_DATA_LEN];/**< Sauvegarde de cle                */
} TC_t_RestoreKey_msg;

/** structure du message pour une requete TC_RestoreKey       */
typedef struct GetObjectAttributes_msg
{
  short   slotId;               /**< identifiant du slot virtuel      */
  short   functionId;           /**< identifiant de la fonction       */
  int     handle;               /**< Handle                           */
  int     offset;               /**< Offset                           */
} TC_t_GetObjectAttributes_msg;


/** structure du message pour une requete TC_TestEcho       */

typedef struct TestEcho_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
  char  varPart[TC_DATA_LEN];       /**< donnees de la partie variable                                                */
  char  testData[TC_DATA_LEN];      /**< donnees de test                                                              */
} TC_t_TestEcho_msg;

/** structure du message pour une requete TC_GetMode       */
typedef struct GetMode_msg
{
  short               slotId;     /**< identifiant du slot virtuel      */
  short               functionId; /**< identifiant de la fonction       */
} TC_t_GetMode_msg;

/** structure des donnees de la reponse pour une requete TC_GetMode       */
typedef struct GetMode_rsp
{
  int       mode;
} TC_t_GetMode_rsp;

/** structure du message pour une requete TC_SetDelayedWrite       */
typedef struct SetDelayedWrite_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_SetDelayedWrite_msg;

/** structure du message pour une requete TC_ResetDelayedWrite       */
typedef struct ResetDelayedWrite_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_ResetDelayedWrite_msg;

typedef struct CIK_reinit_msg
{
  short                      slotId;     /**< identifiant du slot virtuel      */
  short                      functionId; /**< identifiant de la fonction       */
} TC_t_CIK_reinit_msg;

typedef struct Duplicate_cap_msg
{
  short                      slotId;     /**< identifiant du slot virtuel      */
  short                      functionId; /**< identifiant de la fonction       */
} TC_t_Duplicate_cap_msg;

typedef struct TC_HostGetDate_msg
{
    unsigned short	slotID;
    unsigned short	functionID;
} TC_t_HostGetDate_msg;

typedef struct TC_HostGetDate_rsp
{
    unsigned int	date;
} TC_t_HostGetDate_rsp;

typedef struct TC_HostVerifyInit_msg
{
  unsigned short	slotID;
  unsigned short	functionID;
} TC_t_HostVerifyInit_msg;

typedef struct TC_HostVerifyUpdate_msg
{
  unsigned short	slotID;
  unsigned short	functionID;
  unsigned char	    data[4];		// data a verifier
} TC_t_HostVerifyUpdate_msg;
#define TC_HostVerifyUpdateHeaderSize	(sizeof(TC_t_HostVerifyUpdate) - 4)

typedef struct TC_HostVerifyFinal_msg
{
  unsigned short	     slotID;
  unsigned short	     functionID;
  ECC_t_curve_signature	 signature;
} TC_t_HostVerifyFinal_msg;

typedef struct TC_HostGetConfig_msg
{
  unsigned short	slotID;
  unsigned short	functionID;
} TC_t_HostGetConfig_msg;

typedef struct TC_HostGetConfig_rsp
{
  unsigned short	slotID;
  unsigned short	functionID;
  unsigned int	activePartition;
} TC_t_HostGetConfig_rsp;

typedef struct TC_HostSetConfig_msg
{
  unsigned short	slotID;
  unsigned short	functionID;
  unsigned int	activePartition;
} TC_t_HostSetConfig_msg;

#define PART_INIT					0
#define PART_FLIP					1
#define PART_FLOP					2

typedef struct TC_initial_configuration_msg
{
  short               slotId;     /**< identifiant du slot virtuel      */
  short               functionId; /**< identifiant de la fonction       */
} TC_t_initial_configuration_msg;

/** structure du message pour une requete TC_CreateToken      */
typedef struct CreateToken_msg
{
  short slotId;                 /**< identifiant du slot virtuel   */
  short functionId;             /**< identifiant de la fonction    */
  int   labelLen;
  char  label[32];
  int   M;
  int   N;
} TC_t_CreateToken_msg;

/** structure du message pour une requete TC_Install (proche de installation PCA2) */
typedef struct CreateInstallCards_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  unsigned int   M;
  unsigned int   N;
} TC_t_CreateInstallCards_msg;

/** structure du message pour une requete TC_StartPersonalize       */
typedef struct StartPersonalize_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  int                     cik_mode;    // 0 ==> automatique, 1 ==> carte a puce
  unsigned int			  M;		   // si mode carte a puce
  unsigned int			  N;		   // si mode carte a puce, 1 ==> 1 seule carte a puce
  unsigned int            pinLen;      // 0 ==> Trusted Path pour user normal PKCS11
  char                    pin[TC_MAX_PINLEN];
} TC_t_StartPersonalize_msg;

/** structure du message pour une requete TC_CreateUser           */
typedef struct CreateUser_msg
{
  short slotId;                 /**< identifiant du slot virtuel   */
  short functionId;             /**< identifiant de la fonction    */
  int   idLen;
  char  id[1024];
} TC_t_CreateUser_msg;

/** structure du message pour une requete FinishPersonalize_msg       */
typedef struct FinishPersonalize_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
} TC_t_FinishPersonalize_msg;

#define TC_t_unPersonalize_msg TC_t_FinishPersonalize_msg 

typedef struct Login_so_msg
{
  short                      slotId;     /**< identifiant du slot virtuel      */
  short                      functionId; /**< identifiant de la fonction       */
  int                        userType;
} TC_t_Login_so_msg;

/** structure du message pour une requete TC_Start  */
typedef struct StartToken_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  unsigned int   M;
  unsigned int   N;
} TC_t_StartToken_msg;

typedef struct Login_user_msg
{
  short                      slotId;     /**< identifiant du slot virtuel      */
  short                      functionId; /**< identifiant de la fonction       */
  int                        userType;
  unsigned int               pinLen;	 // pinLen = 0 ==> Trusted Path      
  char	                     pin[TC_MAX_PINLEN];					 
} TC_t_Login_user_msg;

typedef struct Logout_msg
{
  short                      slotId;     /**< identifiant du slot virtuel      */
  short                      functionId; /**< identifiant de la fonction       */
} TC_t_Logout_msg;

/** structure d'une requete PCA2_startRestoreKey                */
typedef struct PCA2_StartRestoreKey_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  int                     mode;
} TC_t_PCA2_StartRestoreKey_msg;

/** structure d'une requete PCA2_RestoreSecret                */
typedef struct PCA2_RestoreSecret_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  int                     mode;
} TC_t_PCA2_RestoreSecret_msg;

#define PCA2_MODE_1		0
#define PCA2_MODE_2		1		// 3 parmi 5

/** structure d'une requete PCA2_Derive_Crx */ 
typedef struct DeriveCrx_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                  */
  short functionId;                 /**< identifiant de la fonction                                                   */
  unsigned int   baseKeyHandle;              /**< handle de la cle de base                                                     */
  unsigned int   PCA2_secret_handle;         /**< handle identifiant le secret d'installation PCA2 precedemment entre          */
  unsigned int   seedLen;
  unsigned char  keyAttributes[TC_DATA_LEN]; /**< template cle derivee   suivi du germe                                        */
} TC_t_DeriveCrx_msg;

/** structure d'une requete PCA4_Derive_Crx */ 
typedef struct DeriveCrx_pca4_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                  */
  short functionId;                 /**< identifiant de la fonction                                                   */
  unsigned int   baseKeyHandle;              /**< handle de la cle de base                                                     */
  unsigned int   seedLen;
  unsigned char  keyAttributes[TC_DATA_LEN]; /**< template cle derivee   suivi du germe                                        */
} TC_t_DeriveCrx_pca4_msg;

/** structure d'une requete DERIVE_VPNC */ 
typedef struct Derive_vpnc_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                  */
  short functionId;                 /**< identifiant de la fonction                                                   */
  unsigned int   baseKeyHandle;              /**< handle de la cle de base                                                     */
  unsigned int   idc;
  unsigned int   mechanismType;
  unsigned char  keyAttributes[TC_DATA_LEN]; /**< template cle derivee   suivi du germe                                        */
} TC_t_Derive_vpnc_msg;

/** structure d' une requete PCA2_RestoreKey                */
typedef struct PCA2_RestoreKey_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
  char                    key[0x1000];
} TC_t_PCA2_RestoreKey;

typedef struct GetSlotList_msg
{
  short slotId;      /**< identifiant du slot virtuel       */
  short functionId;  /**< identifiant de la fonction        */
  int tokenPresent;
  int length;
} TC_t_GetSlotList_msg;

typedef struct GetSlotList_rsp
{
  int length;
  int cardIndexList[8];      /**< identifiant du slot virtuel       */
} TC_t_GetSlotList_rsp;

/** structure du message pour une requete TC_SetDate       */
typedef struct SetDate_msg
{
  int date;                     /**< date  */
  short functionId;             /**< identifiant de la fonction   */
} TC_t_SetDate_msg;

/** structure du message pour une requete TC_MasterAuthenticate      */
typedef struct MasterAuthenticate_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_MasterAuthenticate_msg;

/** structure du message pour une requete TC_MasterAuthenticate      */
typedef struct AuditAuthenticate_msg
{
  short slotId;                     /**< identifiant du slot virtuel                                                   */
  short functionId;                 /**< identifiant de la fonction                                                   */
} TC_t_AuditAuthenticate_msg;

/** structure du message pour une requete TCE_DuplicateCard       */
typedef struct DuplicateCap_msg
{
  short                   slotId;      /**< identifiant du slot virtuel       */
  short                   functionId;  /**< identifiant de la fonction        */
} TC_t_DuplicateCap_msg;


#define DERIVE_AES_CBC 0xF0F0
#define DERIVE_AES_ECB 0x0A0A
#define DERIVE_AES_CMAC 0x0424
#define TC_DERIVE_MAX_DATA_LEN 1024

/** \struct Crypto_AES_DERIVE_msg 
 * msg de la requete #Crypto_AES_DERIVE_req
 */
typedef struct Crypto_AES_DERIVE_msg
{
  unsigned short slotId;             /**< identifiant du slot virtuel         */
  unsigned short functionId;         /**< identifiant de la fonction          */
  unsigned int   aes_mode;           /**< mode de derivation (ECB ou CBC)     */
  unsigned int   keyHandle;          /**< handle de la cle de base a deriver  */
  char           iv[AES_BLOCK_SIZE]; /**< iv dans le cas du mode CBC          */
  unsigned int   keyAttrsLen;        /**< longueur en octets des attributs de la cle derivee */
  unsigned int   dataLen;            /**< longueur en octets de la donnee utilisee pour la derivation (multiple d'un bloc AES et maximum 1024 octets) */
} TC_t_Crypto_AES_DERIVE_msg;

#define TC_DERIVE_MAX_DATA_LEN 1024

#define DERIVE_ECDH1_MAX_INFO_LEN 128

typedef struct Crypto_ECDH1_DERIVE_msg
{
  unsigned short slotId;             /**< identifiant du slot virtuel         */
  unsigned short functionId;         /**< identifiant de la fonction          */
  unsigned int   kdfType;            /**< type de KDF (sha256 uniquement)    */
  unsigned int   keyHandle;          /**< handle de la cle de base a deriver  */
  unsigned int   sharedDataLen;      /**< longueur des informations additionnelles          */
  unsigned char  sharedData[DERIVE_ECDH1_MAX_INFO_LEN];      /**< informations additionnelles partagees entre les 2 parties         */
  unsigned int   keyAttrsLen;        /**< longueur en octets des attributs de la cle derivee */
  unsigned int   dataLen;            /**< longueur en octets de la donnee : doit etre sizeof(ECC_t_public_key) */
} TC_t_Crypto_ECDH1_DERIVE_msg;
/*
  datas a envoyer a la suite du message:
   -- attributs PKCS11 de la cle secrete resultat - longueur = keyAttrsLen
   -- cle publique de l'emetteur sous forme de structure ECC_t_public_key (longueur=datalen=sizeof(ECC_t_public_key)
*/

#define DERIVE_TLS_MAX_RANDOM_LEN (32)

typedef struct Crypto_TLS_DERIVE_MASTER_msg
{
  unsigned short 	slotId;             							/**< identifiant du slot virtuel */
  unsigned short 	functionId;         							/**< identifiant de la fonction */
  unsigned int   	keyHandle;          							/**< handle de la cle de base à deriver (sortie ECDH1) */
  unsigned int   	ClientRandomLen;    							/**< longueur du random client */
  unsigned char  	ClientRandom[DERIVE_TLS_MAX_RANDOM_LEN];    	/**< random data du client */
  unsigned int   	ServerRandomLen;    							/**< longueur du random server */
  unsigned char  	ServerRandom[DERIVE_TLS_MAX_RANDOM_LEN];    	/**< random data du server */
  unsigned int   	keyAttrsLen;        							/**< longueur en octets des attributs de la cle derivee */
} TC_t_Crypto_TLS_DERIVE_MASTER_msg;


/** 
 * msg de la requete #Crypto_TLS_DERIVE_K_AND_M_req
 */
typedef struct Crypto_TLS_DERIVE_K_AND_M_msg
{
  unsigned short 	slotId;             							/**< identifiant du slot virtuel */
  unsigned short 	functionId;         							/**< identifiant de la fonction */
  unsigned int   	keyHandle;          							/**< handle de la cle de base à deriver (sortie MASTER_DERIVE) */
  unsigned int   	ClientRandomLen;    							/**< longueur du random client */
  unsigned char  	ClientRandom[DERIVE_TLS_MAX_RANDOM_LEN];    	/**< random data du client */
  unsigned int   	ServerRandomLen;    							/**< longueur du random server */
  unsigned char  	ServerRandom[DERIVE_TLS_MAX_RANDOM_LEN];    	/**< random data du server */
  unsigned int   	keyAttrsLen;        							/**< longueur en octets des attributs des 4 cles derivees */
} TC_t_Crypto_TLS_DERIVE_K_AND_M_msg;


/** 
 * reponse a la requete #Crypto_TLS_DERIVE_K_AND_M_req
 */
typedef struct Crypto_TLS_DERIVE_K_AND_M_rsp
{
  unsigned int  ClientMacHandle;
  unsigned int  ServerMacHandle;
  unsigned int  ClientEncHandle;
  unsigned int  ServerEncHandle;
  unsigned char  IVClient[AES_BLOCK_SIZE];
  unsigned char  IVServer[AES_BLOCK_SIZE];
} TC_t_Crypto_TLS_DERIVE_K_AND_M_rsp;



// structures d'attributs variables entre lib et PCA4
// ==> configuration par defaut

#define CC_DFLT_TOKEN_SECRET_KEY_MAX_NB      140
#define CC_DFLT_SESSION_SECRET_KEY_MAX_NB    250
#define CC_DFLT_SECRET_KEY_LABEL_MAX_LENGTH  128
#define CC_DFLT_SECRET_KEY_ID_MAX_LENGTH     256

#define CC_DFLT_TOKEN_RSA_KEY_MAX_NB         100
#define CC_DFLT_SESSION_RSA_KEY_MAX_NB       200
#define CC_DFLT_RSA_KEY_LABEL_MAX_LENGTH     128
#define CC_DFLT_RSA_KEY_ID_MAX_LENGTH        256
#define CC_DFLT_RSA_KEY_SUBJECT_MAX_LENGTH   256

#define CC_DFLT_TOKEN_ECC_KEY_MAX_NB         100
#define CC_DFLT_SESSION_ECC_KEY_MAX_NB       200
#define CC_DFLT_ECC_KEY_LABEL_MAX_LENGTH     128
#define CC_DFLT_ECC_KEY_ID_MAX_LENGTH        256
#define CC_DFLT_ECC_KEY_SUBJECT_MAX_LENGTH   256

#define CC_DFLT_CERT_MAX_NB                  10
#define CC_DFLT_SESSION_CERT_MAX_NB          0
#define CC_DFLT_CERT_MAX_LENGTH              2048
#define CC_DFLT_CERT_ID_MAX_LENGTH           256
#define CC_DFLT_CERT_LABEL_MAX_LENGTH        128
#define CC_DFLT_CERT_SUBJECT_MAX_LENGTH      256
#define CC_DFLT_CERT_ISSUER_MAX_LENGTH       256
#define CC_DFLT_CERT_SERIAL_MAX_LENGTH       64

#define CC_DFLT_DATA_MAX_NB                  0
#define CC_DFLT_SESSION_DATA_MAX_NB          0
#define CC_DFLT_DATA_MAX_LENGTH              2048
#define CC_DFLT_DATA_ID_MAX_LENGTH           256
#define CC_DFLT_DATA_APPLI_MAX_LENGTH        128
#define CC_DFLT_DATA_LABEL_MAX_LENGTH        128

#define CC_DFLT_PRIV_PUB_FLAGS               0x1111

#define CC_DFLT_SECRET_KEY_MAX_LENGTH        64
#define CC_DFLT_SECRET_KEY_MIN_LENGTH        0

#define CC_DFLT_RSA_KEY_MODULO_MIN_LENGTH    16
#define CC_DFLT_RSA_KEY_MODULO_MAX_LENGTH    512

typedef struct OBJ_DFLT_secretKey_varAttributes
{
  char  wrap_templates[128];
  int   labelLen;
  char  label[CC_DFLT_SECRET_KEY_LABEL_MAX_LENGTH];
  int   idLen;
  char  id[CC_DFLT_SECRET_KEY_ID_MAX_LENGTH];
  int   objType;
  int   valueLen;
} OBJ_t_DFLT_secretKeyVarAttrs;

#define OBJ_DFLT_SECRET_HEADER_SIZE \
(sizeof(OBJ_t_DFLT_secretKeyVarAttrs) + sizeof(TC_t_objectPkcs11AttributesHeader) - 2*sizeof(int))

typedef struct OBJ_DFLT_rsaKey_varAttributes
{
  char  wrap_template[64];
  int  labelLen;
  char label[CC_DFLT_RSA_KEY_LABEL_MAX_LENGTH];
  int  idLen;
  char id[CC_DFLT_RSA_KEY_ID_MAX_LENGTH];
  int  subjectLen;
  char subject[CC_DFLT_RSA_KEY_SUBJECT_MAX_LENGTH];
  int   objType;
  int  modulusLen;      // modulusBits pour cle RSA
} OBJ_t_DFLT_rsaKey_varAttrs;

#define OBJ_DFLT_RSA_HEADER_SIZE \
(sizeof(OBJ_t_DFLT_rsaKey_varAttrs) + sizeof(TC_t_objectPkcs11AttributesHeader) - 2*sizeof(int))

typedef struct OBJ_DFLT_eccKey_varAttributes
{
  char  wrap_template[64];
  int  labelLen;
  char label[CC_DFLT_ECC_KEY_LABEL_MAX_LENGTH];
  int  idLen;
  char id[CC_DFLT_ECC_KEY_ID_MAX_LENGTH];
  int  subjectLen;
  char subject[CC_DFLT_ECC_KEY_SUBJECT_MAX_LENGTH];
  int   objType;
  int  modulusLen;      // longueur de p pour cle ECC
} OBJ_t_DFLT_eccKey_varAttrs;

#define OBJ_DFLT_ECC_HEADER_SIZE \
(sizeof(OBJ_t_DFLT_eccKey_varAttrs) + sizeof(TC_t_objectPkcs11AttributesHeader) - 2*sizeof(int))

typedef struct OBJ_DFLT_cert_varAttributes
{
  int  labelLen;
  char label[CC_DFLT_CERT_LABEL_MAX_LENGTH];
  int  subjectLen;
  char subject[CC_DFLT_CERT_SUBJECT_MAX_LENGTH];
  int  idLen;
  char id[CC_DFLT_CERT_ID_MAX_LENGTH];
  int  issuerLen;
  char issuer[CC_DFLT_CERT_ISSUER_MAX_LENGTH];
  int  serialLen;
  char serial[CC_DFLT_CERT_SERIAL_MAX_LENGTH];
  int  objType;
  int  valueLen;
} OBJ_t_DFLT_cert_varAttrs;

#define OBJ_DFLT_CERT_HEADER_SIZE \
(sizeof(OBJ_t_DFLT_cert_varAttrs) + sizeof(TC_t_objectPkcs11AttributesHeader) - 2*sizeof(int))

typedef struct OBJ_DFLT_data_varAttributes
{
  int  labelLen;
  char label[CC_DFLT_DATA_LABEL_MAX_LENGTH];
  int  appliLen;
  char appli[CC_DFLT_DATA_APPLI_MAX_LENGTH];
  int  idLen;
  char id[CC_DFLT_DATA_ID_MAX_LENGTH];
  int  objType;
  int  valueLen;
} OBJ_t_DFLT_data_varAttrs;

#define OBJ_DFLT_DATA_HEADER_SIZE \
(sizeof(OBJ_t_DFLT_data_varAttrs) + sizeof(TC_t_objectPkcs11AttributesHeader) - 2*sizeof(int))

#ifdef AES_CMAC_CRYPTO

/** \struct Crypto_AES_CMAC_msg 
  * msg de la requête #Crypto_AES_req
*/
typedef struct Crypto_AES_CMAC_msg
{
	unsigned short slotId;        /**< identifiant du slot virtuel       */
	unsigned short functionId;    /**< identifiant de la fonction        */
	unsigned int  aes_cmac_Cmd;   /**< detail de la commande AES                                                     */
	unsigned int  keyHandle;      /**< handle de la 1ere cle requise pour traiter la commande                        */
	char context[AES_BLOCK_SIZE]; /**< contexte dans le cas d'une operation CMAC avec chargement de contexte         */
	unsigned int  signatureLen;   /**< longueur en octets de la signature a generer (comprise entre 12 et 16 octets) */
} TC_t_Crypto_AES_CMAC_msg;

#define CMAC_SIGN_MASK 0xFF000000
#define CMAC_VERI_MASK 0x00FF0000
#define CMAC_CTXT_SAVE_MASK 0x0F
#define CMAC_CTXT_LOAD_MASK 0xF0
#define CMAC_CTXT_MASK 0xFF
#define CMAC_NO_CTXT 0x00

/** \enum cmd_AES_CMAC 
  * liste des commandes possibles envoyees par la lib
*/
enum cmd_AES_CMAC {
	CMAC_SIGN_NO_CTXT             = CMAC_SIGN_MASK, ///< signature sans contexte
	CMAC_SIGN_CTXT_SAVE           = CMAC_SIGN_MASK | CMAC_CTXT_SAVE_MASK,		///< signature avec sauvegarde du contexte 
	CMAC_SIGN_CTXT_LOAD_SAVE      = CMAC_SIGN_MASK | CMAC_CTXT_LOAD_MASK | CMAC_CTXT_SAVE_MASK,	///< signature avec chargement et sauvegarde du contexte 
	CMAC_SIGN_FINAL               = CMAC_SIGN_MASK | CMAC_CTXT_LOAD_MASK,		///< signature avec chargement du contexte 
	CMAC_VERIFY_NO_CTXT           = CMAC_VERI_MASK,	///< verification avec sauvegarde du contexte 
	CMAC_VERIFY_CTXT_SAVE         = CMAC_VERI_MASK | CMAC_CTXT_SAVE_MASK,   ///< verification avec sauvegarde du contexte 
	CMAC_VERIFY_CTXT_LOAD_SAVE    = CMAC_VERI_MASK | CMAC_CTXT_LOAD_MASK | CMAC_CTXT_SAVE_MASK, ///< verification avec chargement et sauvegarde du contexte 
	CMAC_VERIFY_FINAL             = CMAC_VERI_MASK | CMAC_CTXT_LOAD_MASK    ///< verification avec chargement du contexte 
};
#endif // AES_CMAC_CRYPTO

#endif /* TC_LIBRARY_H */
