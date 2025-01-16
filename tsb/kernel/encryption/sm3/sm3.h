#ifndef SM3_H_
#define SM3_H_

#define SM3_DIGEST_SIZE		32

#include <linux/types.h>

struct sm3_context {
	uint32_t total_bytes_High;
	uint32_t total_bytes_Low;
	uint32_t vector[8];
	uint8_t buffer[64];	/* 64 byte buffer                            */

//  unsigned char ipad[64];     /*!< HMAC: inner padding        */
//  unsigned char opad[64];     /*!< HMAC: outer padding        */
};

typedef struct sm3_context sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

	int sm3_starts(sm3_context * index);

/************************************************************************/
/* sm3_init											                    */
/* \brief			初始化 SM3 上下文                                   */
/* \param ctx		SM3 上下文                                          */
/************************************************************************/
	int sm3_init(sm3_context * ctx);

	sm3_context *sm3_alloc_init(void);

/************************************************************************/
/* sm3_update															*/
/* \brief			计算消息摘要										*/
/* \param ctx		SM3 上下文                                          */
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区大小										*/
/************************************************************************/
	int sm3_update(sm3_context * index, const unsigned char *chunk_data,
		       unsigned int chunk_length);

/************************************************************************/
/* sm3_finish															*/
/* \brief			获取摘要值											*/
/* \param ctx		SM3 上下文                                          */
/* \param output	输出缓冲区											*/
/* \remark			输出缓冲取需分配 SM3_DIGEST_SIZE 大小的内存			*/
/************************************************************************/
	int sm3_finish(sm3_context * index,
		       unsigned char output[SM3_DIGEST_SIZE]);

/************************************************************************/
/* sm3																	*/
/* \brief			计算并获取消息摘要值								*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区大小										*/
/* \param output	输出缓冲区											*/
/* \remark			输出缓冲取需分配 SM3_DIGEST_SIZE 大小的内存			*/
/************************************************************************/
	void sm3(const unsigned char *input, int ilen,
		 unsigned char output[SM3_DIGEST_SIZE]);

//int sm3_file( const char *path, unsigned char output[SM3_DIGEST_SIZE] );


#ifdef __cplusplus
}
#endif
#endif				//SM3_H_
