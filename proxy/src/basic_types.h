#ifndef MODULES_TPCMSYS_TPCM_OS_BASIC_TYPES_H_
#define MODULES_TPCMSYS_TPCM_OS_BASIC_TYPES_H_

#include <stddef.h>
#include <stdint.h>
#include <tpcm_config.h>
typedef unsigned char BYTE;
typedef unsigned int BOOL;
#ifndef NULL
#define NULL ((void *)0)
#endif

#define TPCM_TRUE    1
#define TPCM_FALSE   0

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef SYSTEM_ENDIAN_CONV
#ifdef USE_BIG_ENDIAN
#define ntohl(a) (a)
#define ntohs(a) (a)
#define htonl(a) (a)
#define htons(a) (a)
#else
#define ntohl(a) (((uint32_t)(((a)&0xff)<<24)) | ((uint32_t)(((a)&0xff00)<<8)) | ((uint32_t)(((a)&0xff0000)>>8)) | ((uint32_t)(((a)&0xff000000)>>24)))
#define ntohs(a) (((uint16_t)(((a)&0xff)<<8)) | ((uint16_t)(((a)&0xff00)>>8)))
#define htonl(a)  (ntohl(a))
#define htons(a)  (ntohs(a))
#endif
#else
#include <netinet/in.h>
#endif
//
//((uint64_t)) << 32)
#ifndef USE_BIG_ENDIAN
#define ntoh64(a)  (((uint64_t)ntohl((uint32_t)(a))) << 32 | ntohl((uint32_t)(((uint64_t)(a)) >> 32)))
#define swap_word(a) ((((uint32_t)a)<< 16) | (((uint32_t)a)>>16))
#else
#define ntoh64(a) (a)
#define swap_word(a) (a)
#endif


struct measure_addr_seg{
	uint64_t address;
	uint32_t length;
} __attribute__((packed));

#ifndef CONFIG_SM3_CONTEXT_MAX_SIZE
#define CONFIG_SM3_CONTEXT_MAX_SIZE (0x200)
#endif

struct sm3_ctx_common{
	unsigned char context[CONFIG_SM3_CONTEXT_MAX_SIZE];
};

#ifndef CONFIG_SM4_CONTEXT_MAX_SIZE
#define CONFIG_SM4_CONTEXT_MAX_SIZE 320
#endif

struct sm4_ctx_common{
	unsigned char context[CONFIG_SM4_CONTEXT_MAX_SIZE];
};


#endif /* MODULES_TPCMSYS_TPCM_OS_BASIC_TYPES_H_ */
