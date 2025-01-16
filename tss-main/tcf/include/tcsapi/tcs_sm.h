
#ifndef __TCS_SM_H__
#define __TCS_SM_H__

#include <stdint.h>

#define SM3_UPDATE_SIZE_LIMIT		0xA000000	/** 160MB */

typedef unsigned char SM3_DIGEST[32];

int tcs_sm3_init (void** ctx);
int tcs_sm3_update (void* ctx, const uint8_t *input, int ilen);
int tcs_sm3_finish (void* ctx, SM3_DIGEST output);

/** 运用SM3算法对指定数据计算摘要值 */
int tcs_sm3 (const uint8_t *input, int ilen, uint8_t *output, int *olen);

/** 运用SM3算法对指定数据摘要值进行验证 奔图项目 */
int tcs_sm3_verify(const uint8_t *data, uint32_t len, const uint8_t *verify, uint32_t size);

/** 运用SM4-CBC算法对指定数据进行加密，key为明文密钥 */
int tcs_sm4_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** 运用SM4-ECB算法对指定数据进行加密，key为明文密钥 */
int tcs_sm4_ecb_encrypt(uint8_t *key, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** 运用SM4-CBC算法对指定数据进行解密，key为明文密钥 */
int tcs_sm4_cbc_decrypt(uint8_t *key, uint8_t *iv,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);
/** 运用SM4-ECB算法对指定数据进行解密，key为明文密钥 */
int tcs_sm4_ecb_decrypt(uint8_t *key, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen);

/** 运用SM2算法对指定数据的摘要值进行签名 */
int tcs_sm2_sign (uint8_t *privkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t *siglen);

/** 运用SM2算法对指定数据的摘要值进行验签 */
int tcs_sm2_verify (uint8_t *pubkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t siglen);

/** 运用SM2算法对指定数据的摘要值进行验签 奔图项目*/
/*
功能 : 通过可信根使用 SM2 算法验签，并在可信根串口打印信息
参数 : public_key: 公钥
hash: 固件摘要值
sign: 签名数据
返回值 : 0 成功、其他失败
其他要求 :可信根通过串口，打印 public_key、 hash、 sign、验证结果
*/
int tcs_sm2_verify_b(const uint8_t *pubkey, uint32_t keylen, const uint8_t *hash, uint32_t hashlen, const uint8_t *sign, uint32_t siglen);

/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行签名 */
int tcs_sm2_sign_e (uint8_t *privkey, uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t *siglen);

/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行验签  */
int tcs_sm2_verify_e (uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t siglen);

/** 获取随机数 */
int tcs_random (uint8_t *data, uint32_t size);

/** 对HASH签名 */
int tcs_hash_sign(uint32_t index, uint8_t *digest, uint8_t *sig);

#endif	/** __TCS_SM_H__ */

