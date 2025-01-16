#ifndef __TCS_SM_H__
#define __TCS_SM_H__

#include <stdint.h>

/** 运用SM3算法对指定数据计算摘要值 */
int tcs_sm3 (const uint8_t *input, int ilen, uint8_t *output, int *olen);

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

/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行签名 */
int tcs_sm2_sign_e (uint8_t *privkey, uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t *siglen);

/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行验签  */
int tcs_sm2_verify_e (uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t siglen);


/** 获取随机数 */
int tcs_random (uint8_t *data, uint32_t size);

#endif	/** __TCS_SM_H__ */

