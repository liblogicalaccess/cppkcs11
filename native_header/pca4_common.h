#ifndef __PCA4_COMMON_H_
#define __PCA4_COMMON_H_

#define PCA4_MAX_HSM        10

#define ASN1_ISO_0          42
#define ASN1_ISO_US_0       0x86
#define ASN1_ISO_US_1       0x48
#define ASN1_X9_62_0        0xCE
#define ASN1_X9_62_1        0x3D
#define ASN1_X9_62_EC       3
#define ASN1_X9_62_EC_P     1

#define EC_ASN1_UNCOMPRESS_POINT 4

#define AES_BLOCK_SIZE      16
#define DES_BLOCK_SIZE      8

#define MAX_RSA_MODULUS_BITS 4096
#define MAX_RSA_MODULUS_LEN  ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS   ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN    ((MAX_RSA_PRIME_BITS + 7) / 8)


// Pour padding a 16, on rajoute 1 a 16 octets (16 octets si deja aligne)
#define AES_ALIGN16(s)		(((s) + 16) & 0xFFFFFFF0)
#define AES_PADDING16(s)	(AES_ALIGN16(s) - (s))

// Pour padding a 4
#define RSC_ALIGN4(x)		(((x) & 3) ? (((x) | 3) + 1) : (x))

// Taille No de serie, on aligne le buffer sur 4 octets
#define PCA4_SERIAL_NUMBER_SIZE		19
#define PCA4_SERIAL_NUMBER_BUFSIZE	((PCA4_SERIAL_NUMBER_SIZE + 3) & ~3)


//==========================================
// Courbes elliptiques
//==========================================
#define ECC_MAX_P_LEN          68          // ==> courbe NIST 521 bits (arrondi au multiple de 4 superieur: 544 bits)
                                           // pour une courbe utilisateur max = 512 bits

#define ECC_ECDSA_SIGTYPE      0
										  
//=============================================
// Signature ECDSA ou ECKCDSA sur courbe jusqu' a 544 bits
//=============================================
typedef struct ECC_struct_curve_signature
{
    unsigned char mechanism[4];
    unsigned char size[4];            // 2 * size(r) (size(r) = size(s))
    unsigned char r[ECC_MAX_P_LEN];
    unsigned char s[ECC_MAX_P_LEN];
} ECC_t_curve_signature;

#define ECC_m_set_signature_mechanism(S, n) do { \
  (S)->mechanism[0] = (unsigned char)((n) >> 24); (S)->mechanism[1] = (unsigned char)((n) >> 16); \
  (S)->mechanism[2] = (unsigned char)((n) >> 8); (S)->mechanism[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_signature_mechanism(S) (((int)((S)->mechanism[0]) << 24) + ((int)((S)->mechanism[1]) << 16) + ((int)((S)->mechanism[2]) << 8) + (int)((S)->mechanism[3]))

#define ECC_m_set_signature_size(S, n) do { \
  (S)->size[0] = 0; (S)->size[1] = 0; \
  (S)->size[2] = (unsigned char)((n) >> 8); (S)->size[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_signature_size(S) (((int)((S)->size[2]) << 8) + (int)((S)->size[3]))

//==========================================
// Parametres de courbe jusqu' a 544 bits (68 octets)
//==========================================
typedef struct ECC_struct_curve_parameters
{
    unsigned char p[ECC_MAX_P_LEN];
    unsigned char a[ECC_MAX_P_LEN];
    unsigned char b[ECC_MAX_P_LEN];
    unsigned char x[ECC_MAX_P_LEN];
    unsigned char y[ECC_MAX_P_LEN];
    unsigned char order[ECC_MAX_P_LEN];
}  ECC_t_curve_parameters;

#define ECC_CURVE_MAX_BLACK_SIZE (6 * ECC_MAX_P_LEN)
typedef struct EEC_struct_curve_ref
{
    unsigned char cofactor[4];
    unsigned char modulus_len[4];            // Big endian taille de la courbe en octets cadree 4: 512 bits -> 64 octets, 521 bits -> 68 octets
    struct
    {
        union uparams
        {
            ECC_t_curve_parameters params;
            unsigned char param[ECC_CURVE_MAX_BLACK_SIZE];
        } u;
        unsigned char padding[AES_PADDING16(sizeof(union uparams))];
    } p_align16;
} ECC_t_curve_ref;

// Parametres a noircir cadres en debut de zones
// Padding avec random avant noircissement

#define ECC_m_CURVE_set_cofactor(c, n) do { \
  (c)->cofactor[0] = 0; (c)->cofactor[1] = 0; \
  (c)->cofactor[2] = (unsigned char)((n) >> 8); (c)->cofactor[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_curve_cofactor(c)    (((int)((c)->cofactor[2]) << 8) + (int)((c)->cofactor[3]))

#define ECC_m_set_curve_params_modulus_len(c, n) do { \
  (c)->modulus_len[0] = 0; (c)->modulus_len[1] = 0; \
  (c)->modulus_len[2] = (unsigned char)((n) >> 8); (c)->modulus_len[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_curve_params_modulus_len(c) (((int)((c)->modulus_len[2]) << 8) + (int)((c)->modulus_len[3]))

#define ECC_m_get_curve_params_modulus_order_1st_int(c) (((int)(((c)->p_align16.u.params.order)[0]) << 24) + ((int)(((c)->p_align16.u.params.order)[1]) << 16) + ((int)(((c)->p_align16.u.params.order)[2]) << 8) + (int)(((c)->p_align16.u.params.order)[3]))

//==========================================
// CLE PUBLIQUE
//==========================================
typedef struct ECC_struct_point
{
    unsigned char x[ECC_MAX_P_LEN];
    unsigned char y[ECC_MAX_P_LEN];
    unsigned char padding[AES_PADDING16(2 * ECC_MAX_P_LEN)];
} ECC_t_point;

typedef struct EEC_struct_public_key
{
    unsigned char size_x[4];            // = size(x)
    unsigned char size_y[4];            // = size(y)
    ECC_t_point   point;
} ECC_t_public_key;

// Cle cadree en debut de zone avec padding a 0 a gauche pour que size = (modulus en octets)

// Pour les points compresses, on l'indique dans size_y:
#define ECC_COMPRESSED_ODD_Y  0xFFFFFFFF
#define ECC_COMPRESSED_EVEN_Y 0xFFFFFFFE

#define ECC_m_set_public_key_size_x(Q, n) do { \
  (Q)->size_x[0] = (unsigned char)((n) >> 24); (Q)->size_x[1] = (unsigned char)((n) >> 16); \
  (Q)->size_x[2] = (unsigned char)((n) >> 8); (Q)->size_x[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_public_key_size_x(Q) (((int)((Q)->size_x[0]) << 24) + ((int)((Q)->size_x[1]) << 16) + ((int)((Q)->size_x[2]) << 8) + (int)((Q)->size_x[3]))

#define ECC_m_set_public_key_size_y(Q, n) do { \
  (Q)->size_y[0] = (unsigned char)((n) >> 24); (Q)->size_y[1] = (unsigned char)((n) >> 16); \
  (Q)->size_y[2] = (unsigned char)((n) >> 8); (Q)->size_y[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_public_key_size_y(Q) (((int)((Q)->size_y[0]) << 24) + ((int)((Q)->size_y[1]) << 16) + ((int)((Q)->size_y[2]) << 8) + (int)((Q)->size_y[3]))

//==========================================
// CLE PRIVEE
//==========================================
#define ECC_D_MAX_BLACK_SIZE ECC_MAX_P_LEN

typedef struct EEC_struct_private_key
{
    unsigned char size[4];                    // size(p) (p, a, b, x, y, order sont de la même taille)
    struct
    {
        unsigned char d[ECC_D_MAX_BLACK_SIZE];    // taille reelle = size(p) 
        unsigned char padding[AES_PADDING16(ECC_D_MAX_BLACK_SIZE)];
    } d_align16;
} ECC_t_private_key;

// Parametres a noircir cadres en debut de zones
// Padding avec random avant noircissement

#define ECC_m_set_private_key_size(d, n) do { \
  (d)->size[0] = 0; (d)->size[1] = 0; \
  (d)->size[2] = (unsigned char)((n) >> 8); (d)->size[3] = (unsigned char)(n); \
} while (0)
#define ECC_m_get_private_key_size(d) (((int)((d)->size[2]) << 8) + (int)((d)->size[3]))

// Parametres pour signature EC-KCDSA

// Identifiant du signataire, structure utilisee dans la signature EC-KCDSA
typedef struct ECC_struct_sign_id {
    unsigned char    size[4];	// Longueur de l'Id du signataire (big Endian)
    unsigned char    id[16];   	// Id du signataire (doit être multiple de 16 pour chiffrement AES)
} ECC_t_sign_id;

#define ECC_m_get_sign_id_size(c) (((int)((c)->size[2]) << 8) + (int)((c)->size[3]))


#define ERR_OK					0

#define CKM_VERIFY_SHA256_ECDSA		0x8000080B
#define CKM_VERIFY_SHA512_ECDSA		0x8000080C
#define CKM_VERIFY_SHA256_ECKCDSA	0x8000080D
#define CKM_VERIFY_SHA512_ECKCDSA	0x8000080E

#endif
