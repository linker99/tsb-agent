#ifndef __SM2_IF_H__
#define __SM2_IF_H__

#include <stdlib.h>
#include "./sm3.h"

#define IN
#define OUT
#define IO

#define SM2_BIGNUM_BUFSIZE		32

typedef struct {
    unsigned int bits;
    unsigned char d[SM2_BIGNUM_BUFSIZE];
}SM2_PRIVATE_KEY;

typedef struct {
    unsigned int bits;
    unsigned char x[SM2_BIGNUM_BUFSIZE];
    unsigned char y[SM2_BIGNUM_BUFSIZE];
}SM2_PUBLIC_KEY;

typedef struct {
    unsigned char r[SM2_BIGNUM_BUFSIZE];
    unsigned char s[SM2_BIGNUM_BUFSIZE];
}SM2_SIGNATURE;

/* sm2 interface */

int os_sm2_generate_key(OUT unsigned char **privkey, OUT unsigned int *privkey_len,
                        OUT unsigned char **pubkey, OUT unsigned int *pubkey_len);

int os_sm2_generate_key_ex(SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);

int os_generate_param_z(IN unsigned char *pubkey, IN unsigned int pubkey_len,
                        IN  unsigned char *ID, IN unsigned id_len, OUT unsigned char z[32]);
#if 0
int os_sm2_sign_withz(IN const unsigned char *dgst, IN int dlen,
                      IN unsigned char *privkey, IN unsigned int privkey_len, IN unsigned char z[32],
                      OUT unsigned char **sig, OUT unsigned int *siglen);
#endif
int os_sm2_sign(IN const unsigned char *msg, IN int msglen,
                IN unsigned char *privkey, IN unsigned int privkey_len,
                unsigned char *pubkey, unsigned int pubkey_len,
                OUT unsigned char **sig, OUT unsigned int *siglen);

int os_sm2_verify(IN const unsigned char *msg, IN int msglen,
                  IN unsigned char *pubkey, IN unsigned int pubkey_len,
                  IN unsigned char *sig, IN  unsigned int siglen);

int os_sm2_encrypt (
    IN unsigned char *plain_text, IN unsigned int plain_text_len,
    IN unsigned char *pubkey, IN unsigned int pubkey_len,
    OUT unsigned char **cipher_text, OUT unsigned int *cipher_text_len);
int os_sm2_decrypt (
    IN unsigned char *cipher_text, IN unsigned int cipher_text_len,
    IN unsigned char *prikey, IN unsigned int prikey_len,
    OUT unsigned char **plain_text, OUT unsigned int *plain_text_len);
int os_sm2_dh_key(
			const unsigned char Za[SM3_DIGEST_SIZE],/** 本地个人信息摘要 */
			const unsigned char Zb[SM3_DIGEST_SIZE],/** 对方个人信息摘要 */
			const SM2_PRIVATE_KEY *prikey_static_a,	/** 本地静态密钥私钥 */
			const SM2_PUBLIC_KEY *pubkey_static_b,	/** 对方静态密钥公钥信息 */
			SM2_PRIVATE_KEY *prikey_temp_a,			/** 本地临时密钥私钥 */
			SM2_PUBLIC_KEY *pubkey_temp_a,			/** 本地临时密钥公钥 */
			SM2_PUBLIC_KEY *pubkey_temp_b,			/** 对方临时密钥公钥信息 */	
			unsigned int okeylen,					/** 协商出的密钥信息长度 */
			unsigned char *outkey,					/** 协商出的密钥信息 */
			unsigned char S1[SM3_DIGEST_SIZE],		/** 本地验证数据 */
			unsigned char SA[SM3_DIGEST_SIZE], int role);		/** 提供对方验证数据 */
void os_sm_kdf(const unsigned char *share, unsigned int sharelen, unsigned int keylen, unsigned char *outkey);



#define SM2_MALLOC(size) malloc(size)
#define SM2_FREE(ptr) free(ptr)

#endif	/** __SM2_IF_H__ */

