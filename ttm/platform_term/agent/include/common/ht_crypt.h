#ifndef __HTTC_CRYPT_H__
#define __HTTC_CRYPT_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define SM3_DIGEST_SIZE		32

struct ttm_sm3_context {
  uint32_t total_bytes_High;
  uint32_t total_bytes_Low;
  uint32_t vector[8];
  uint8_t  buffer[64];

//  unsigned char ipad[64];     /*!< HMAC: inner padding        */
//  unsigned char opad[64];     /*!< HMAC: outer padding        */
};

typedef struct ttm_sm3_context ttm_sm3_context;

#ifdef __cplusplus
extern "C" {
#endif


/************************************************************************/
/* ttm_sm3_init											                    */
/* \brief			初始化 SM3 上下文                                   */
/* \param ctx		SM3 上下文                                          */
/************************************************************************/
int ttm_sm3_init( ttm_sm3_context *ctx );


/************************************************************************/
/* ttm_sm3_update															*/
/* \brief			计算消息摘要										*/
/* \param ctx		SM3 上下文                                          */
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区大小										*/
/************************************************************************/
int ttm_sm3_update(ttm_sm3_context *index, const unsigned char *chunk_data, unsigned int chunk_length);

/************************************************************************/
/* ttm_sm3_finish															*/
/* \brief			获取摘要值											*/
/* \param ctx		SM3 上下文                                          */
/* \param output	输出缓冲区											*/
/* \remark			输出缓冲取需分配 SM3_DIGEST_SIZE 大小的内存			*/
/************************************************************************/
int ttm_sm3_finish( ttm_sm3_context *index, unsigned char output[SM3_DIGEST_SIZE] );

int ttm_sm3_file(const char *path, unsigned char *output);



/* sm4 start */

#define ENCRYPT  0			// 定义加密标志
#define DECRYPT  1			// 定义解密标志

#define BLOCK_SIZE 16
#define SM4_ENC_SIZE(len)	((len / BLOCK_SIZE + 1 ) * BLOCK_SIZE)

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif


typedef struct _sms4_key{
	unsigned int m_key[4];
	unsigned int m_encrypt_rk[33];
	unsigned int m_decrypt_rk[33];
}ttm_sms4_key;



/* sm4 end */



#ifdef __cplusplus
}
#endif


#endif
