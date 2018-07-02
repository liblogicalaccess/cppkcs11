#ifndef ADMINTCE_H	
#define ADMINTCE_H 


#include <stdio.h>
#include <sys/stat.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <fcntl.h>		/* For O_RDWR value */
#include "cryptoki.h"

/* Descriptor fields for C_SoftwareUpdate_Token */

#define CC2_VERSIONS_NAME     "versions"
#define CC2_SOFTWARE_NAME     "crypto"
#ifdef PCA4_USB
#define CC2_FPGA_LOW_NAME         "fpga_usb"
#else
#define CC2_FPGA_LOW_NAME         "fpga_low"
#endif
#define CC2_FPGA_HIGH_NAME         "fpga_high"
#define CC2_VERSIONS_SOFTWARE_NAME "versions.dat"


#ifdef PCA4_OEM
#define SYS_IMAGE_NAME     "oem_linux"
#define SYS_SIGNATURE_NAME "oem_linux"
#define SYS_VERSIONS_SOFTWARE_NAME "releases.dat"
#else
#define SYS_IMAGE_NAME     "pca4_linux_prod"
#define SYS_SIGNATURE_NAME "pca4_linux_prod"
#define SYS_VERSIONS_SOFTWARE_NAME "releases.dat"
#endif

#define CKA_PHYSICAL_HANDLE  0x80000000|0x00000008

#define TCE_FILENAME_LEN 32
#define TCE_SOFTWARE_VERSION_LEN 4
#define TCE_SOFTWARE_NUMBER 4 // versions, crypto fpga_low fpga_high
#define SYS_SOFTWARE_VERSION_LEN 4
#define SYS_SOFTWARE_NUMBER 2 // pca4_linux_prod.img pca4_linux_prod.sig

typedef struct TCE_SOFTWARE_DESC {
    char codeFileName[TCE_FILENAME_LEN];
    CK_ULONG codeFileLen;   
    short codeFileType;   
} TCE_SOFTWARE_DESC;

typedef TCE_SOFTWARE_DESC CK_PTR TCE_SOFTWARE_DESC_PTR;

// structure pour TCE_Initialize (applicative mutexes can't be used)
typedef struct TCE_INIT_ARGS {
    CK_ULONG ssl;        // 0 pas de ssl, 1 ssl
    CK_CHAR ServCertName[256];
    CK_CHAR ClntCertName[256]; // rfu
} TCE_INIT_ARGS;

typedef  TCE_INIT_ARGS CK_PTR TCE_INIT_ARGS_PTR;

// structure pour TCE_Initialize_v1 (applicative mutexes can be used)
typedef struct TCE_INIT_ARGS_V1 {         // RFU
    CK_ULONG ssl;         // 0 pas de ssl, 1 ssl
    CK_CHAR ServCertName[256];
    CK_CHAR ClntCertName[256]; // rfu
	CK_VOID_PTR pInitArgs; // to pass eventual applicative mutex functions
	} TCE_INIT_ARGS_V1;

typedef  TCE_INIT_ARGS_V1 CK_PTR TCE_INIT_ARGS_V1_PTR;

#ifdef PCA4

#define PART_HPA		0x00000000
#define PART_MBR_P0		0x00000001
#define PART_CODE_P1	0x00000002
#define PART_P3			0x00000003
#define PART_P4			0x00000004

#define FLAG_SIGN		(1 << 0)
#define FLAG_ZERO		(1 << 1)
#define FLAG_ADD_LENGTH	(1 << 2)
#define FLAG_COMPRESS	(1 << 3)

#ifndef MIN
#define MIN(a, b)	((a) < (b) ? a : b)
#endif
#define SWAP32(val)	( ((u_int32_t)(val) << 24) | \
					 (((u_int32_t)(val) << 8)  & 0x00FF0000) | \
					 (((u_int32_t)(val) >> 8)  & 0x0000FF00) | \
					  ((u_int32_t)(val) >> 24) )

#define SWAP64(val)	( ((u_int64_t)(val) << 56) | \
					 (((u_int64_t)(val) << 40) & 0x00FF000000000000ULL) | \
					 (((u_int64_t)(val) << 24) & 0x0000FF0000000000ULL) | \
					 (((u_int64_t)(val) << 8)  & 0x000000FF00000000ULL) | \
					 (((u_int64_t)(val) >> 8)  & 0x00000000FF000000ULL) | \
					 (((u_int64_t)(val) >> 24) & 0x0000000000FF0000ULL) | \
					 (((u_int64_t)(val) >> 40) & 0x000000000000FF00ULL) | \
					  ((u_int64_t)(val) >> 56) )

#define PACKED	__attribute__ ((packed))

#define DISK_SECT_SIZE	512
#define DISK_SEC_COUNT	20
#define DISK_FREE_SECT	2

#define FS_FAT16_LBA	0x0E
#define FS_FAT32_LBA	0x0C
#define FS_LINUX		0x83

#define FS_SUPERBLOCK_OFFSET	1024

#define MBR_MAGIC			0xAA55

struct partinfo
{
	u_int8_t	status;
	u_int8_t	chs_first1;
	u_int8_t	chs_first2;
	u_int8_t	chs_first3;
	u_int8_t	type;
	u_int8_t	chs_last1;
	u_int8_t	chs_last2;
	u_int8_t	chs_last3;
	u_int32_t	lba_first_sector;
	u_int32_t	sectors;
} PACKED;

struct mbr_info
{
	u_int32_t	disk_signature;
	u_int16_t	nulls;
	struct partinfo	partition[4];
	u_int16_t	mbr_signature;
} PACKED;

struct mbr
{
	char 			code[DISK_SECT_SIZE - sizeof(struct mbr_info)];
	struct mbr_info	info;
} PACKED;

struct header
{
	u_int32_t	version;
	u_int32_t	part_count;
} PACKED;

struct part_header
{
	u_int32_t	part_version;
	u_int32_t	part_type;
	u_int32_t	part_flags;
	u_int32_t	part_length;
} PACKED;

struct part_compress_header
{
	u_int64_t	size;
};

struct part_compress_trailer
{
	u_int8_t	hash[32];
};

#define SIGNATURE_SIZE	144

#endif

/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_ADMIN_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

#include "admin_tcef.h"

#undef CK_NEED_ARG_LIST
#undef CK_ADMIN_FUNCTION_INFO


/* ==============================================================
 * Define the typedef form of all the entry points.  That is, for
 * each admin function TC_XXX, define a type CK_TC_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */
#define __PASTE(x,y)      x##y

#define CK_NEED_ARG_LIST  1
#define CK_ADMIN_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))


/* function prototypes. */
#include "admin_tcef.h"

#undef CK_NEED_ARG_LIST
#undef CK_ADMIN_FUNCTION_INFO

#undef __PASTE

#endif /* ADMINTCE_H */

//#endif /* ADMINTCE_H */
