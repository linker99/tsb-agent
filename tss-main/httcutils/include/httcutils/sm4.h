#ifndef _SM4_H_
#define _SM4_H_

//#include "typedef.h"

//struct sm4_ctx_common;

#define FM_ALGMODE_ECB 0
#define FM_ALGMODE_CBC 1

int ht_sm4_setkey_enc(void *ctx,
		const unsigned char *key, int len);
int ht_sm4_setkey_dec(void *ctx,
		const unsigned char *key, int len);

void ht_sm4_ecb_encrypt(void *ctx, int len,
		const unsigned char *in,  unsigned char *out);

void ht_sm4_ecb_decrypt(void *ctx, int len,
		const unsigned char *in,  unsigned char *out);

void ht_sm4_cbc_encrypt(void *ctx, int len,
		const unsigned char *iv,
		const unsigned char *in,  unsigned char *out);

void ht_sm4_cbc_decrypt(void *ctx, int len,
		const unsigned char *iv,
		const unsigned char *in,  unsigned char *out);
int ht_sm4_encrypt( uint8_t *key, uint8_t *in_iv, uint32_t mode, uint8_t *input, 
					uint32_t ilen, uint8_t *output, uint32_t *olen);

int  ht_sm4_decrypt( uint8_t *key, uint8_t *in_iv, uint32_t mode, uint8_t *input,
					uint32_t ilen, uint8_t *output, uint32_t *olen); 
//int ht_sm4_check(int ctx_size);
#endif /* _SM4_H_ */
