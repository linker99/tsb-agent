/**
 * \file sm4.h
 */
#ifndef __SM4_H__
#define __SM4_H__


#define FM_ALGMODE_ECB	0
#define FM_ALGMODE_CBC	1

/**
 * \brief          SM4 context structure
 */
typedef struct {
    unsigned long sk[32];       /*!<  SM4 subkeys       */
    unsigned char iv[16];		/*!<  SM4 iv			*/
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/************************************************************************/
/* sm4_importkey				                                        */
/* \brief			导入key 和 iv                                       */
/* \param ctx		SM4 上下文                                          */
/* \param key		SM4 密钥											*/
/* \param iv		SM4 CBC 模式初始向量								*/
/************************************************************************/
void httc_sm4_importkey(sm4_context *ctx, unsigned char key[16], unsigned char iv[16]);

/************************************************************************/
/* sm4_encrypt															*/
/* \brief			使用 ctx 中 key 及 iv 加密							*/
/* \param ctx		SM4 上下文                                          */
/* \param mode		加密模式 FM_ALGMODE_ECB / FM_ALGMODE_CBC			*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区大小										*/
/* \param output	输出缓冲区											*/
/* \param olen		输出缓冲区大小										*/
/* \remark			output 传入 NULL 时仅返回长度，否则需分配足够的内存	*/
/************************************************************************/
void httc_sm4_encrypt(sm4_context *ctx, int mode, unsigned char *input, int ilen,
                 unsigned char *output, int *olen);

/************************************************************************/
/* sm4_decrypt															*/
/* \brief			使用 ctx 中 key 及 iv 解密							*/
/* \param ctx		SM4 上下文                                          */
/* \param mode		加密模式 FM_ALGMODE_ECB / FM_ALGMODE_CBC			*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区大小										*/
/* \param output	输出缓冲区											*/
/* \param olen		输出缓冲区大小										*/
/* \remark			output 需分配与输入同样大小的内存					*/
/************************************************************************/
void httc_sm4_decrypt(sm4_context *ctx, int mode, unsigned char *input, int ilen,
                 unsigned char *output, int *olen);

#ifdef __cplusplus
}
#endif	/** __SM4_H__ */

#endif
