#ifndef __TCSK_SM_H__
#define __TCSK_SM_H__

#define SM3_UPDATE_SIZE_LIMIT		0xA000000	/** 160MB */	

typedef unsigned char SM3_DIGEST[32];

int tcsk_sm3_init (void** ctx);

int tcsk_sm3_update (void* ctx, const uint8_t *input, int ilen);

int tcsk_sm3_finish (void* ctx, SM3_DIGEST output);

/** 运用SM3算法对指定数据计算摘要值 */
int tcsk_sm3 (const uint8_t *input, int ilen, uint8_t *output, int *olen);

#endif	/** __TCSK_SM_H__ */

