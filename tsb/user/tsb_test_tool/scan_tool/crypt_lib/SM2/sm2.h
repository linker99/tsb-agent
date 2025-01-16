#include "ec.h"
#include "../SM3/sm3.h"

#define SM2_ERR_NOERR			0
#define SM2_ERR_INIT_FAILED		1
#define SM2_ERR_MALLOC_FAILED	2
#define SM2_ERR_BAD_PARAM		3
#define SM2_ERR_EC_LIB			4
#define SM2_ERR_BN_LIB			5
#define SM2_ERR_RANDOM_FAILED	6
#define SM2_ERR_BAD_SIGNATURE	7
#define SM2_ERR_PRIVATEKEY		8
#define SM2_ERR_PUBLICKEY		9
#define SM2_ERR_DECRYPT			10
#define SM2_ERR_DH_FAILED		11

#define SM2_BIGNUM_BUFSIZE		32
#define SM2_ECPOINT_BUFSIZE		65

typedef struct  
{
	unsigned int bits;
	unsigned char d[SM2_BIGNUM_BUFSIZE];
} SM2_PRIVATE_KEY;

typedef struct
{
	unsigned int bits;
	unsigned char x[SM2_BIGNUM_BUFSIZE];
	unsigned char y[SM2_BIGNUM_BUFSIZE];
} SM2_PUBLIC_KEY;

typedef struct  
{
	unsigned char r[SM2_BIGNUM_BUFSIZE];
	unsigned char s[SM2_BIGNUM_BUFSIZE];
} SM2_SIGNATURE;

#ifdef __cplusplus
extern "C" {
#endif


/************************************************************************/
/* sm2_init																*/
/* \brief			初始化椭圆曲线参数                                  */
/* \param ecgroup	椭圆曲线参数                                        */
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			sm2_init_standard 用于验证技术规范					*/
/************************************************************************/
int sm2_init(EC_GROUP **ecgroup);
int sm2_init_standard(EC_GROUP **ecgroup);

/************************************************************************/
/* sm2_cleanup															*/
/* \brief			释放椭圆曲线参数占用的内存                          */
/* \param ecgroup	椭圆曲线参数                                        */
/************************************************************************/
void sm2_cleanup(EC_GROUP *ecgroup);

/************************************************************************/
/* sm2_gen_keypair														*/
/* \brief			产生公私钥对	                                    */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param privatekey私钥												*/
/* \param publickey	公钥												*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			privatekey/publickey 传入 NULL 时仅返回长度，		*/
/*					否则需分配足够的内存								*/
/*					sm2_init_standard* 用于验证技术规范					*/
/************************************************************************/
int sm2_gen_keypair(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard1(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard2_a(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard2_b(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard3(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);
int sm2_gen_keypair_standard5(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey);

/************************************************************************/
/* sm2_dh_key															*/
/* \brief			基于 ECC 产生共享密钥                               */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param Za		发起方身份信息										*/
/* \param Zb		接收方身份信息										*/
/* \param privatekey私钥												*/
/* \param publickey	对方公钥											*/
/* \param a_r		己方随机数											*/
/* \param R_b		对方椭圆曲线点										*/
/* \param keylen	需要获取的共享密钥长度								*/
/* \param keylen	共享密钥输出缓冲区									*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			sm2_init_standard* 用于验证技术规范					*/
/************************************************************************/
int sm2_dh_key(const EC_GROUP *ecgroup, const unsigned char Za[SM3_DIGEST_SIZE], const unsigned char Zb[SM3_DIGEST_SIZE],
	const SM2_PRIVATE_KEY *a_pri_key, const SM2_PUBLIC_KEY *b_pub_key, const unsigned char a_r[SM2_BIGNUM_BUFSIZE],
	const unsigned char R_b[SM2_ECPOINT_BUFSIZE], unsigned int keylen, unsigned char *outkey);

/************************************************************************/
/* sm2_encrypt															*/
/* \brief			公钥加密		                                    */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param publickey	公钥												*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区长度										*/
/* \param output	输出缓冲区											*/
/* \param olen		输出缓冲区长度										*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			output 传入 NULL 时仅返回长度，否则需分配足够的内存	*/
/* \remark			sm2_encrypt_standard 用于验证技术规范				*/
/************************************************************************/
int sm2_encrypt(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);
int sm2_encrypt_standard(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);

/************************************************************************/
/* sm2_decrypt															*/
/* \brief			私钥解密		                                    */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param publickey	私钥												*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区长度										*/
/* \param output	输出缓冲区											*/
/* \param olen		输出缓冲区长度										*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			output 传入 NULL 时仅返回长度，否则需分配足够的内存	*/
/************************************************************************/
int sm2_decrypt(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char *input, unsigned int ilen,
	unsigned char *output, unsigned int *olen);

/************************************************************************/
/* sm2_sign																*/
/* \brief			私钥签名		                                    */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param privatekey私钥												*/
/* \param Z			签名者身份信息										*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区长度										*/
/* \param output	签名结果											*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			input 在内部使用 SM3 算法进行摘要					*/
/*					sm2_sign_standard 用于验证技术规范					*/
/************************************************************************/
int sm2_sign(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output);
int sm2_sign_standard(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output);

/************************************************************************/
/* sm2_verify															*/
/* \brief			公钥验证		                                    */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param publickey	公钥												*/
/* \param Z			签名者身份信息										*/
/* \param input		输入缓冲区											*/
/* \param ilen		输入缓冲区长度										*/
/* \param signature	签名数据											*/
/* \return			0 成功，失败返回相应错误代码						*/
/* \remark			input 在内部使用 SM3 算法进行摘要					*/
/************************************************************************/
int sm2_verify(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, const SM2_SIGNATURE *signature);

/************************************************************************/
/* sm_gen_random														*/
/* \brief			随机数发生器		                                */
/* \param len		需要产生的随机数长度								*/
/* \param output	输出缓冲区											*/
/* \return			1 成功，0 失败										*/
/************************************************************************/
int sm_gen_random(unsigned int len, unsigned char *output);

/************************************************************************/
/* sm2_dh_gen_random													*/
/* \brief			密钥协商所需的随机数发生器                          */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param r			随机数												*/
/* \param R			椭圆曲线点的二进制表示								*/
/* \return			0 成功，失败返回相应错误代码						*/
/*					sm2_dh_gen_random_standard* 用于验证技术规范		*/
/************************************************************************/
int sm2_dh_gen_random(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);
int sm2_dh_gen_random_standard_a(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);
int sm2_dh_gen_random_standard_b(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE]);

/************************************************************************/
/* sm_kdf																*/
/* \brief			密钥派生函数				                        */
/* \param share		共享密钥缓冲区                                      */
/* \param sharelen	共享密钥缓冲区长度									*/
/* \param keylen	要获得的密钥数据的长度								*/
/* \param keylen	输出密钥缓冲区										*/
/************************************************************************/
void sm_kdf(const unsigned char *share, unsigned sharelen, unsigned keylen, unsigned char *outkey);

/************************************************************************/
/* sm2_Z																*/
/* \brief			生成用户身份信息			                        */
/* \param ecgroup	椭圆曲线参数                                        */
/* \param ID		用户 ID												*/
/* \param idlen		用户 ID	长度										*/
/* \param publickey	公钥												*/
/* \param dgst		输出缓冲区											*/
/* \return			0 成功，失败返回相应错误代码						*/
/************************************************************************/
int sm2_Z(const EC_GROUP *ecgroup, const unsigned char *ID, unsigned short idlen, const SM2_PUBLIC_KEY *publickey, unsigned char dgst[SM3_DIGEST_SIZE]);


#define SM2_MALLOC(size) sm2_malloc(size, __FILE__, __LINE__)
#define SM2_FREE(ptr) sm2_free(ptr, __FILE__, __LINE__)

void *sm2_malloc(size_t size,  const char *file, int line);
void sm2_free(void *ptr,  const char *file, int line);




#ifdef __cplusplus
}
#endif
