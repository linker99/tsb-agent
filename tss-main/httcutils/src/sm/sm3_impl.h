/*
 * sm3_impl.h
 *
 *  Created on: 2019 年12 月 5 日
 *      Author: wangtao
 */

#ifndef MODULES_SYSTEM_SM_SM3_IMPL_H_
#define MODULES_SYSTEM_SM_SM3_IMPL_H_

#include <stdint.h>

#define SM3_DIGEST_SIZE		32


#ifndef CONFIG_SM3_CONTEXT_MAX_SIZE
#define CONFIG_SM3_CONTEXT_MAX_SIZE (0x200)
#endif

struct sm3_ctx_common{
	unsigned char context[CONFIG_SM3_CONTEXT_MAX_SIZE];
};

typedef struct sm3_context
{
  uint32_t total_bytes_High;
  uint32_t total_bytes_Low;
  uint32_t vector[8];
  uint8_t  buffer[64];
}sm3_context;
//int sm3_finup(void *ctx, const unsigned char *data, int len, unsigned char *out);

#endif /* MODULES_SYSTEM_SM_SM3_IMPL_H_ */
