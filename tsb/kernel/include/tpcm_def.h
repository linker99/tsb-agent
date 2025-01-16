#ifndef __TPCM_DEF_H__
#define __TPCM_DEF_H__
#include <linux/version.h>


#if defined(CONFIG_CSKY) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define IS_BIG_ENDIAN    0 
#else
#define IS_BIG_ENDIAN    (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#endif

typedef union {
	uint64_t u64;
	struct {
		uint32_t u32_h;
		uint32_t u32_l;
	};
} Uint64_u;

static inline uint64_t Convert64(uint64_t h64)
{
	Uint64_u In64, Out64;
	In64.u64 = h64;
	Out64.u32_h = htonl(In64.u32_l);
	Out64.u32_l = htonl(In64.u32_h);
	return Out64.u64;
}

#define HTONS(h)	htons(h)
#define HTONL(h)	htonl(h)
#define NTOHS(n)	ntohs(n)
#define NTOHL(n)	ntohl(n)
#if IS_BIG_ENDIAN
#define HTONLL(h)	(h)
#define NTOHLL(n)	(n)
#else
#define HTONLL(h)	Convert64(h)
#define NTOHLL(n)	Convert64(n)
#endif

enum TPCM_LOG_TYPE {
	TPCM_LOG_TYPE_BMEASURE = 1,
	TPCM_LOG_TYPE_DMEASURE = 2,
	TPCM_LOG_TYPE_MAX
};

#endif // __TPCM_DEF_H__
