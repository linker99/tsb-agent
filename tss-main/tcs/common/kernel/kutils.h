#ifndef __TCSK_UTILS_H__
#define __TCSK_UTILS_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <asm/cacheflush.h>

#pragma pack(push, 1)
struct tpcm_data{
	int be_size;
	uint8_t value[0];
};
struct tpcm_auth{
	uint32_t be_type;
	int be_size;
	uint8_t value[0];
};
#pragma pack(pop)

#define httc_align_size(len,align) ((len)%(align) == 0 ? (len) : (len) + (align) - (len)%(align))
#define MIN(x,y) ((x)<(y)?(x):(y))

#ifdef __BIG_ENDIAN_BITFIELD
#define htonll(val) (val)
#define ntohll(val) (val)
#else
static inline uint64_t htonll(uint64_t val)
{
	return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
}
static inline  uint64_t ntohll(uint64_t val)
{
	return (((uint64_t)ntohl(val)) << 32) + ntohl(val >> 32);
}
#endif

extern unsigned long k_kallsyms_lookup_name;
extern unsigned long (*httc_kallsyms_lookup_name) (const char *name);
extern void httc_arch_invalidate_pmem(void *addr, size_t size);
char* tpcm_memcpy(void __iomem *dst, const void *src, int size);
char* tpcm_memcpy_u16(void __iomem *dst, const uint16_t src);
char* tpcm_memcpy_u32(void __iomem *dst, const uint32_t src);
char* tpcm_memcpy_u64(void __iomem *dst, const uint64_t src);
char* tpcm_memclear(void __iomem *dst, int size);
void httc_util_str2array (uint8_t *output, uint8_t *input, uint32_t insize);
int tpcm_util_cache_flush (void *kaddr, size_t len);
int encodeDER_4signout (unsigned char *srcsignbuf, unsigned char *outbuf);
void httc_util_time_print (const char *format, uint64_t time);
int httc_insert_uid_align4 (const char *uid, void *ptr);
int httc_insert_auth_align4 (int auth_type, int auth_length,unsigned char *auth, void *ptr);
int httc_insert_data_align4 (const char *data, int size, void *ptr);
int httc_insert_data (const char *data, int size, void *ptr);
int httc_extract_uid_align4_size (void *ptr);
int httc_extract_auth_align4_size (void *ptr);

#ifdef __cplusplus
}
#endif

#endif	/** __TCSK_UTILS_H__ */


