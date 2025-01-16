#ifndef _SM4_H_
#define _SM4_H_

//#include "typedef.h"

//struct sm4_ctx_common;
typedef struct sm4_ctx_impl{
	u32 sk_enc[32];
	u32 sk_dec[32];
	u32 iv[16];
}sm4_ctx_common;

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
#endif /* _SM4_H_ */
