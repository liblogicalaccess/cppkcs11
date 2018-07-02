/** @file
    Definition des structures utilisateur specifiques aux requetes du token.
*/

#ifndef TC_USER_LIB_H
#define TC_USER_LIB_H

/******************************************* 
        Types PKCS11 specifiques
********************************************/
#define CKK_ECC_KCDSA		            0x80001000

/******************************************* 
        Mecanismes PKCS11 specifiques
********************************************/
#define CKM_PCA2_DERIVE_CRX		        0x80000804
#define CKM_PCA4_DERIVE_MASTER_KEY		0x80000805
#define CKM_SAVE_RESTORE_KEY			0x80000806
#define CKM_PCA4_DERIVE_VPNC		    0x80000807
#define CKM_PCA4_DERIVE_VPNC_AES		0x80000808
#define CKM_AES_CMAC_DERIVE				0x80000810

/******************************************* 
        Mecanismes specifiques PCA4
********************************************/
#define CKM_VERIFY_SHA512_ECC512	    0x8000080B
#define CKM_ECDSA_SHA256				0x80001000
#define CKM_ECDSA_SHA384				0x80001001
#define CKM_ECDSA_SHA512				0x80001002
#define CKM_ECKCDSA_KEY_PAIR_GEN        0x80001010
#define CKM_ECKCDSA				        0x80001020
#define CKM_SOFTWARE_SIGN				0x80001030
#define CKM_AES_CMAC_GENERAL            0x00001089
#define CKM_AES_CMAC                    0x0000108A
#define CKM_DES3_CMAC_GENERAL           0x00000137
#define CKM_DES3_CMAC                   0x00000138

/******************************************* 
        Parametres des mecanismes
           PKCS11 specifiques
********************************************/
typedef struct CK_ECKCDSA_PARAMS {
	unsigned int hashAlg; // CK_MECHANISM_TYPE
	unsigned char *pSignId;
	unsigned int ulSignId;
} CK_ECKCDSA_PARAMS;
typedef CK_ECKCDSA_PARAMS CK_PTR CK_ECKCDSA_PARAMS_PTR;

typedef struct CK_DERIVE_MASTER_KEY_PARAMS { 
    unsigned int PCA2_secret_handle;
	unsigned int  seedLen;
	unsigned char *seed;
} CK_DERIVE_MASTER_KEY_PARAMS;
typedef CK_DERIVE_MASTER_KEY_PARAMS CK_PTR CK_DERIVE_MASTER_KEY_PARAMS_PTR;
typedef struct CK_DERIVE_VPNC_PARAMS { 
	unsigned int   idc;
 } CK_DERIVE_VPNC_PARAMS;
typedef CK_DERIVE_VPNC_PARAMS CK_PTR CK_DERIVE_VPNC_PARAMS_PTR;

/******************************************* 
        Codes fichier pour SoftwareUpdate
********************************************/
#define TC_FILE_TYPE_FPGA_CODE          4
#ifdef PCA4_USB
#define TC_FILE_TYPE_FPGA_USB_CODE      8
#endif
#define TC_FILE_TYPE_SOFT_CODE          2
#define TC_FILE_TYPE_VERSIONS_DAT		16

/******************************************* 
    Structure des informations du token 
    pour une requete PCA4_getTokenStatus 
********************************************/
#define TC_TOKEN_INFO_VERSION 0
typedef struct TokenStatus_4
{
  int   infoVersion;              /**< Version de TokenStatus                  */
  unsigned int  VersionMcs;
  unsigned int  VersionBitstream;
#ifdef PCA4_USB
  unsigned int  VersionBitstreamUsb;
#endif
  unsigned int  VersionCrypto;
  unsigned int  VersionVersionsDat;
  char  serialNumber[16];         /**< numero de serie du HSM                  */
  int   HSM_state;                /**< etat du HSM virtuel(token) interroge    */
  int   HSM_extState;
  int   index;          
  int   num_digit;          
  int   slot_flags;               /**< flags du HSM virtuel interroge   */
  int   token_flags;              /**< flags du HSM virtuel interroge   */
  char  label[32];
} TC_t_TokenStatus_4;

/* valeur du champ statusToken */
#define TC_STATE_SORTIE_FAB               0x0001 /**< sortie de la fabrication usine    */
#define TC_STATE_FIRST_USE                0x0008
#define TC_STATE_CREATE_SO_MASTER         0x000A
#define TC_STATE_CREATE_AUDIT_MASTER      0x000C

#define TC_STATE_HSM_NULL                 0
#define TC_STATE_HSM_ENTER_K_SAVE		  0x0014
#define TC_STATE_HSM_GEN_CIK              0x0018
#define TC_STATE_HSM_CREATE_SO            0x0020
#define TC_STATE_HSM_CREATE_AUDIT         0x0024
#define TC_STATE_HSM_PPC                  0x0028  /** SO cree, pret pour personnalisation */
#define TC_STATE_HSM_PKCS11_USER_CREATED  0x0030
#define TC_STATE_HSM_OPERATIONNEL         0x0040  /** personnalisation terminee **/

#define TC_STATE_MASK					  0x00FF

#define TC_STATE_SO_MASTER_LOGGED         0x0100  // authentifie pour une commande
#define TC_STATE_AUDIT_MASTER_LOGGED      0x0200  // authentifie pour une commande

#define TC_STATE_HSM_WAITING_CIK          0x0400
#define TC_STATE_HSM_USER_LOGGED          0x0800
#define TC_STATE_HSM_SO_LOGGED            0x1000
#define TC_STATE_HSM_AUDIT_LOGGED         0x2000

#define TC_STATE_HSM_ABORT_REQUEST         0x4000   // erreur => req doit etre terminee

#define TC_EXT_STATE_CREATE_USER           0x0001   // creation user non normal (1 ou plusieurs dans etat TC_STATE_HSM_USER_CREATED)
#define TC_EXT_STATE_LOGIN_USER            0x0002   // authentification en cours d'un des users non normaux pour une commande
#define TC_EXT_STATE_LOGIN_PKCS11_USER     0x0006
#define TC_EXT_STATE_LOGIN_PKCS11_SO       0x0008
#define TC_EXT_STATE_LOGIN_AUDIT           0x000C   // authentification en cours pour une commande
#define TC_EXT_STATE_LOGIN_SO_MASTER       0x0010   // authentification en cours pour une commande
#define TC_EXT_STATE_LOGIN_AUDIT_MASTER    0x0020   // authentification en cours pour une commande
#define TC_EXT_STATE_ENTER_K_SAVE_PCA2     0x00FF

#define TC_EXT_STATE_MASK				   0x00FF

#define TC_EXT_STATE_INSERT_SMC            0x0100
#define TC_EXT_STATE_REMOVE_SMC            0x0200
#define TC_EXT_STATE_ENTER_PIN             0x0400
#define TC_EXT_STATE_DEFINE_PIN            0x0800
#define TC_EXT_STATE_CONFIRM_PIN           0x1000

// constantes pour slot_flags (HSM0)
#define CKF_FPGA_MODEL 						0x80000000
#define CKF_FPGA_MODEL_HIGH					0x80000000
#define CKF_FPGA_MODEL_LOW					0x00000000
// definit si la plateforme est un TDM de remplacement PCA2
#define CKF_PLATEFORME_MODEL_TDM			0x40000000
#define CKF_PLATEFORME_MODEL				0x40000000
// definit le nombre de HSM virtuel(s) disponibles(s) (3 derniers bits + 1)
#define CKF_HSMV_MAX						0x00000007

#define CKF_HARDWARE_MODEL					0x40000000
#define CKF_HARDWARE_MODEL_TDM				0x40000000

#define CKF_NBHSMV_MODEL					0x00000007

#ifdef PCA4_USB
// constantes pour token flags (HSM0 et HSM10)
#define CKF_LOW_BATTERY						0x00000001
#define CKF_ALIM_KO							0x00000002
#endif

/******************************************* 
   Structure de la configuration du token
   pour une requete C_GetConfiguration
********************************************/
#define TC_PROFIL_SIZE    16
#define TC_MAX_OPTIONS	  16

typedef struct TokenConfiguration_4
{
  int   version;
  int   flags;			// 0xFF ==> parametres de dimensionnement siginificatifs, 0xFF00 profil (+ options) significatif

  int   nb_max_cles_secretes;
  int   nb_max_cles_RSA;
  int   nb_max_cles_ECC;
  int   nb_max_data;
  int   nb_max_certificats;

  int   nb_max_cles_secretes_session;
  int   nb_max_cles_RSA_session;
  int   nb_max_cles_ECC_session;
  int   nb_max_certificats_session;
  int   nb_max_data_session;

  int   lg_max_label_cle_secrete;
  int   lg_max_ID_cle_secrete;

  int   lg_max_label_cle_RSA;
  int   lg_max_ID_cle_RSA;
  int   lg_max_subject_cle_RSA;

  int   lg_max_label_cle_ECC;
  int   lg_max_ID_cle_ECC;
  int   lg_max_subject_cle_ECC;

  int   lg_max_label_certificat;
  int   lg_max_ID_certificat;
  int   lg_max_subject;
  int   lg_max_issuer;
  int   lg_max_serial_number;
  int   lg_max_certificat;

  int   lg_max_label_data;
  int   lg_max_appli_data;
  int   lg_max_ID_data;     // ==> CKA_OBJECT_ID
  int   lg_max_data;

  int   profil[TC_PROFIL_SIZE];
  int   nOptions;
  int   options[TC_MAX_OPTIONS];
} TC_t_TokenConfiguration_4;

/********************************
Options
Contraintes sur longueur des cles utilisees
0 ==> max generic key size (0 ==> 64 octets)
1 ==> min generic key size (0 ==> 4 octets)
2 ==> max rsa modulus size (0 ==> 512 octets)
3 ==> min rsa modulus size (0 ==> 64 octets)
4 ==> max rsa public exponent size (0 ==> 32 octets)
5 ==> min rsa public exponent size (0 ==> 1 octet)
6 ==> max ecc curve size (0 ==>  521 bits)
7 ==> min  ecc curve size (0 ==> 112 bits)

Contre mesures RSA ou ECC
8 ==> Timing Attack (0x7)  + Fault Attack (0x38)
*********************************/

/*******************************************************
        Interdictions mecanismes (champ profil)
********************************************************/
#define TC_m_CONF_FLAG_TST(n, flag) (((flag) & (7 << ((n)*3))) == (7 << ((n)*3)))

#define TC_CONF_FORBID_G_DES3                0
#define TC_CONF_FORBID_C_DES3_ECB            1
#define TC_CONF_FORBID_C_DES3_CBC            2
#define TC_CONF_FORBID_W_DES3_ECB            4
#define TC_CONF_FORBID_W_DES3_CBC            5
#define TC_CONF_FORBID_W_DES3_CBC_PAD        6
#define TC_CONF_FORBID_CREATE_DES3           7
#define TC_CONF_FORBID_DES3					 8

#define TC_m_CONF_DES3_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[0])

#define TC_CONF_FORBID_G_AES                 0
#define TC_CONF_FORBID_C_AES_ECB             1
#define TC_CONF_FORBID_C_AES_CBC             2
#define TC_CONF_FORBID_W_AES_ECB             3
#define TC_CONF_FORBID_W_AES_CBC             4
#define TC_CONF_FORBID_W_AES_CBC_PAD         5
#define TC_CONF_FORBID_CREATE_AES            6
// 7 reserve

#define TC_m_CONF_AES_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[1])

#define TC_CONF_FORBID_G_RSA                 0
#define TC_CONF_FORBID_C_PKCS                1
#define TC_CONF_FORBID_S_PKCS                2
#define TC_CONF_FORBID_W_PKCS                3
#define TC_CONF_FORBID_S_PSS                 4
#define TC_CONF_FORBID_W_OAEP                5
#define TC_CONF_FORBID_C_OAEP                6
#define TC_CONF_FORBID_W_X509                7
#define TC_CONF_FORBID_C_X509                8
#define TC_CONF_FORBID_CREATE_PRIV_RSA       9

#define TC_m_CONF_RSA_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[2])

#define TC_CONF_FORBID_G_GENERIC             0
#define TC_CONF_FORBID_MD5					 1
#define TC_CONF_FORBID_SHA1					 2
#define TC_CONF_FORBID_SHA256				 3
#define TC_CONF_FORBID_SHA384				 4
#define TC_CONF_FORBID_SHA512				 5
#define TC_CONF_FORBID_CREATE_GENERIC        6

#define TC_m_CONF_HMAC_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[3])

#define TC_CONF_FORBID_G_DES                0
#define TC_CONF_FORBID_C_DES_ECB            1
#define TC_CONF_FORBID_C_DES_CBC            2
#define TC_CONF_FORBID_CREATE_DES           6
#define TC_CONF_FORBID_G_DES2               7
#define TC_CONF_FORBID_CREATE_DES2          8
#define TC_CONF_FORBID_DES				    9

#define TC_m_CONF_DES_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[5])

#define TC_CONF_FORBID_G_ECC                 0
#define TC_CONF_FORBID_S_ECDSA               1
#define TC_CONF_FORBID_CREATE_PRIV_ECC		 2
#define TC_CONF_FORBID_G_ECKCDSA             4
#define TC_CONF_ALLOW_SOFTWARE_SIGN	         5
#define TC_CONF_FORBID_CREATE_PRIV_ECC_KCDSA 6

#define TC_m_CONF_ECC_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[6])

#define TC_CONF_FORBID_W_D                   1
// PR_459 Ajout des mecanismes de double authentification forcee
// la valeur 2 est reservee pour le mode FIPS en version non evaluee
#define TC_CONF_RESORE_DOUBLE_AUTHENT		 3
#define TC_CONF_SAVE_DOUBLE_AUTHENT			 4

#define TC_m_CONF_SECU_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[7])

#define TC_CONF_FORBID_DERIVE_AES_CBC        0
#define TC_CONF_FORBID_DERIVE_AES_ECB        1
#define TC_CONF_FORBID_DERIVE_AES_CMAC       2
#define TC_CONF_FORBID_DERIVE_ECDH1          3
#define TC_CONF_FORBID_DERIVE_TLS_MK_DH      4
#define TC_CONF_FORBID_DERIVE_TLS_K_AND_M    5

#define TC_m_CONF_DERIVE_FLAG_TST(n, flags)	 TC_m_CONF_FLAG_TST(n, (flags)[8])

// mode de la fonction TCE_SetLibMode
// un seul fd pour tout le process (mode par defaut)
#define TC_LIB_MODE_NORMAL                   0
// autant de fd vers le driver que de threads (cnx RPC_client)
#define TC_LIB_MODE_PCA4_NETHSM_SERVER       1

// Table des evenements du journal 

#define TOKEN_EVT_RAZ 		      	0x100
#define TOKEN_EVT_INIT          	0x101
#define TOKEN_EVT_INIT_PREPERSO       	0x102
#define TOKEN_EVT_INIT_CONFIG_INITIALE 	0x103
#define TOKEN_EVT_BIST_DES_1		0x104
#define TOKEN_EVT_BIST_DES_2         	0x105
#define TOKEN_EVT_BIST_AES_1  		0x106
#define TOKEN_EVT_BIST_AES_2 		0x107
#define TOKEN_EVT_BIST_KEYH		0x108
#define TOKEN_EVT_BIST_SHA256		0x109
#define TOKEN_EVT_BIST_HMAC_SHA256_1	0x10a
#define TOKEN_EVT_BIST_HMAC_SHA256_2	0x10b
#define TOKEN_EVT_BIST_SHA512		0x10c
#define TOKEN_EVT_BIST_HMAC_SHA512_1	0x10d	
#define TOKEN_EVT_BIST_HMAC_SHA512_2	0x10e
#define TOKEN_EVT_BIST_MD5		0x10f
#define TOKEN_EVT_BIST_HMAC_MD5_1	0x110 
#define TOKEN_EVT_BIST_HMAC_MD5_2	0x111 
#define TOKEN_EVT_BIST_HMAC_SHA1_1	0x112 
#define TOKEN_EVT_BIST_HMAC_SHA1_2	0x113 
#define TOKEN_EVT_CREATE_HSMV		0x114 
#define TOKEN_EVT_DELETE_HSMV		0x115 
#define HSM_EVT_PERSO			0x116 
#define HSM_EVT_DEPERSO			0x117 
#define HSM_EVT_START			0x118 
#define HSM_EVT_GET_CIK_CAP		0x119 
#define HSM_EVT_SET_CONFIGURATION	0x11a 
#define HSM_EVT_LOGIN_CHECK_CONFIG	0x11b 
#define TOKEN_EVT_SO_MASTER_LOGIN	0x11c 
#define TOKEN_EVT_AUDIT_MASTER_LOGIN	0x11d 
#define TOKEN_EVT_SO_MASTER_LOGOUT	0x11e 
#define TOKEN_EVT_AUDIT_MASTER_LOGOUT	0x11f 
#define HSM_EVT_SO_LOGIN		0x120 
#define HSM_EVT_AUDIT_LOGIN		0x121 
#define HSM_EVT_USER_LOGIN		0x122 
#define HSM_EVT_SO_LOGOUT		0x123
#define HSM_EVT_AUDIT_LOGOUT		0x124
#define HSM_EVT_USER_LOGOUT		0x125 
#define TOKEN_EVT_SOFTWARE_UPDATE	0x126 
#define TOKEN_EVT_HOST_VERIFY		0x127 
#define HSM_EVT_SECURE_MESSAGING	0x128 
#define HSM_EVT_MUTUAL_AUTHENTIFICATION	0x129 
#define HSM_EVT_VERIFY_PIN		0x12a 
#define HSM_EVT_RESTORE_KEY		0x12b 
#define HSM_EVT_RESTORE_SECRET_KEY	0x12c 
#define HSM_EVT_RESTORE_RSA_KEY	0x12d 
#define HSM_EVT_RESTORE_ECC_KEY	0x12e 
#define HSM_EVT_PCA2_RESTORE_KEY_START	0x12f 
#define HSM_EVT_PCA2_RESTORE_KEY	0x130

// type de carte
#define CARD_TYPE_SO_MASTER		0x11AA                             
#define CARD_TYPE_AUDIT_MASTER  	0x22BB                     
#define CARD_TYPE_SO            	0x33CC           
#define CARD_TYPE_AUDIT         	0x44DD              
#define CARD_TYPE_CIK_0	       		0x5550              
#define CARD_TYPE_CIK_1	        	CARD_TYPE_CIK_0 + 1              
#define CARD_TYPE_CIK_2	        	CARD_TYPE_CIK_0 + 2              
#define CARD_TYPE_CIK_3	        	CARD_TYPE_CIK_0 + 3              
#define CARD_TYPE_CIK_4	        	CARD_TYPE_CIK_0 + 4              
#define CARD_TYPE_CIK_5	        	CARD_TYPE_CIK_0 + 5              
#define CARD_TYPE_CIK_6	        	CARD_TYPE_CIK_0 + 6              
#define CARD_TYPE_CIK_7	        	CARD_TYPE_CIK_0 + 7              
#define CARD_TYPE_CIK_8	        	CARD_TYPE_CIK_0 + 8              
#define CARD_TYPE_CIK_9	        	CARD_TYPE_CIK_0 + 9              
#define CARD_TYPE_INSTALL_0     	0x6660           
#define CARD_TYPE_INSTALL_1	    	CARD_TYPE_INSTALL_0 + 1              
#define CARD_TYPE_INSTALL_2	    	CARD_TYPE_INSTALL_0 + 2              
#define CARD_TYPE_INSTALL_3	    	CARD_TYPE_INSTALL_0 + 3              
#define CARD_TYPE_INSTALL_4	    	CARD_TYPE_INSTALL_0 + 4              
#define CARD_TYPE_INSTALL_5	    	CARD_TYPE_INSTALL_0 + 5              
#define CARD_TYPE_INSTALL_6	    	CARD_TYPE_INSTALL_0 + 6              
#define CARD_TYPE_INSTALL_7	    	CARD_TYPE_INSTALL_0 + 7              
#define CARD_TYPE_INSTALL_8	    	CARD_TYPE_INSTALL_0 + 8              
#define CARD_TYPE_INSTALL_9	    	CARD_TYPE_INSTALL_0 + 9

#endif /* TC_USER_LIB_H */
