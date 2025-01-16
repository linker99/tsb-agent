#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include "tpcm_error_all.h"
#include "tcs_error.h"
//#include "tpcm_utils.h"
#include "tpcm_command.h"
//#include "tpcm_measure.h"
//#include "tpcm_sm.h"
#include "transmit.h"
#include "tcs_sm.h"
#include "tcs_constant.h"
#include "debug.h"
#include "mem.h"
#include "tcmfunc.h"
#include "tcs_config.h"
#include "uutils.h"

#define HTONL(h) htonl(h)
#define NTOHL(n) ntohl(n)

#define ALLOC_SIZE 4096
#define REFERENCE_CMD_SIZE 0x200000
#define MinLicReqLength 26
#define MinLicLength 95

#define TPCM_REF_BMEASURE_ITEM_SIZE 36
#define TPCM_REF_IMEASURE_ITEM_SIZE 32

#define TPCM_AUTH_SIZE 32

#define SEG_LIMIT_SIZE (64*1024)
typedef unsigned char SM3_CONTEXT[512];

#pragma pack(push, 1)
typedef struct
{
	COMMAND_HEADER;
	uint32_t size;
} sm3_req_st;

typedef struct
{
	RESPONSE_HEADER;
	uint8_t digest[DEFAULT_HASH_SIZE];
} sm3_rsp_st;

typedef struct{
	SM3_CONTEXT context;
	int datalen;
	uint8_t data[SEG_LIMIT_SIZE];
} tcs_sm3_context_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t ctx_len;
	uint8_t ctx[0];
}sm3_init_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ctx_len;
	SM3_CONTEXT ctx;
	uint32_t size;
}sm3_user_update_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t ctx_len;
	uint8_t ctx[0];
}sm3_update_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ctx_len;
	tcs_sm3_context_st ctx;
}sm3_finish_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}sm3_finish_rsp_st;

typedef struct
{
	COMMAND_HEADER;
	uint8_t privkey[SM2_PRIVATE_KEY_SIZE];
	uint8_t pubkey[SM2_PUBLIC_KEY_SIZE];
	uint32_t size;
} sm2_sign_req_st;

typedef struct
{
	RESPONSE_HEADER;
	uint8_t sig[DEFAULT_SIGNATURE_SIZE];
} sm2_sign_rsp_st;

typedef struct
{
	COMMAND_HEADER;
	uint8_t pubkey[SM2_PUBLIC_KEY_SIZE];
	uint8_t sig[DEFAULT_SIGNATURE_SIZE];
	uint32_t size;
} sm2_verify_req_st;

typedef struct
{
	COMMAND_HEADER;
	uint32_t publen;
	uint8_t pubkey[SM2_PUBLIC_KEY_SIZE];
	uint32_t diglen;
	uint8_t digest[TPCM_AUTH_SIZE];
	uint32_t siglen;
	uint8_t sig[DEFAULT_SIGNATURE_SIZE];
} sm2_verify_b_req_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t  privkey[SM2_PRIVATE_KEY_SIZE];
	uint8_t  digest[TPCM_AUTH_SIZE];
}sm2_sign_e_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t  sig[DEFAULT_SIGNATURE_SIZE ];
}sm2_sign_e_rsp_st;


typedef struct{
	COMMAND_HEADER;
	uint8_t  pubkey[SM2_PUBLIC_KEY_SIZE];
	uint8_t  digest[TPCM_AUTH_SIZE];
	uint8_t  sig[DEFAULT_SIGNATURE_SIZE];
}sm2_verify_e_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t  iv[SM4_IV_SIZE];
	uint32_t size;
}sm4_encrypt_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t size;
}sm4_encrypt_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t  iv[SM4_IV_SIZE];
	uint32_t size;
}sm4_decrypt_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t size;
}sm4_decrypt_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t index;
	uint8_t  digest[TPCM_AUTH_SIZE];
}hash_sign_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t  sig[DEFAULT_SIGNATURE_SIZE];
}hash_sign_rsp_st;

#pragma pack(pop)

int tcs_sm3_init (void** ctx)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *req = NULL;
	sm3_init_rsp_st *rsp = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_sm3_context_st *cntx = NULL;

	if (NULL == (cntx = httc_malloc (sizeof (tcs_sm3_context_st)))){
		httc_util_pr_error ("Context Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cntx);
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st*)buffer;
	rsp = (sm3_init_rsp_st*)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	req->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl (sizeof (tpcm_req_header_st));
	req->uiCmdCode = htonl (TPCM_ORD_SM3_INIT);

	if (0 != (ret = tpcm_transmit (req, sizeof (tpcm_req_header_st), rsp, &rspLen))) goto err;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto err;
	}

	if ((ret = tpcmRspRetCode (rsp))) goto out;

	if(tpcmReqLength(rsp) <= sizeof(sm3_init_rsp_st)){
		httc_util_pr_error ("Error response (length:%d < length:%ld)\n",
							 tpcmReqLength(rsp), (long int)sizeof(sm3_init_rsp_st));
		ret = TSS_ERR_BAD_RESPONSE;
		goto err;
	}

	if(tpcmReqLength(rsp) != (sizeof(sm3_init_rsp_st) + ntohl (rsp->ctx_len))){
		httc_util_pr_error ("Error response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_init_rsp_st) + ntohl (rsp->ctx_len), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto err;
	}

	if (ntohl (rsp->ctx_len) > sizeof (SM3_CONTEXT)){
		httc_util_pr_error("tcs sm3 context is not enough (%d < %ld)\n", ntohl (rsp->ctx_len), (long int)sizeof (SM3_CONTEXT));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto err;
	}

	memcpy (cntx->context, (void*)rsp->ctx, ntohl (rsp->ctx_len));
	cntx->datalen = 0;
	*ctx = cntx;
	goto out;

err:
	if (cntx) httc_free (cntx);
out:
	if (buffer) httc_free (buffer);
	return ret;
}

int tcs_sm3_update (void* ctx, const uint8_t *input, int ilen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm3_user_update_req_st *cmd = NULL;
	sm3_update_rsp_st *rsp = NULL;
	tcs_sm3_context_st *cntx = (tcs_sm3_context_st*)ctx;
	int total_len = ilen + cntx->datalen;
	int next_len = 0;
	int update_len = 0;

	if(ilen > TPCM_SM3_LIMIT){
		httc_util_pr_error("tcs sm3 update input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if (total_len < SEG_LIMIT_SIZE){
		memcpy (cntx->data + cntx->datalen, input, ilen);
		cntx->datalen += ilen;
		return TSS_SUCCESS;
	}

	next_len = total_len % SEG_LIMIT_SIZE;
	update_len = total_len - next_len;

	if ((fd = open("/dev/httctcs", O_RDWR)) < 0)
	{
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if ((ubuf = mmap(NULL, (size_t)update_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		httc_util_pr_error("######### Mmap Failed, size = %d\n", update_len);
		close(fd);
		return TSS_ERR_MAP;
	}
	memcpy(ubuf, cntx->data, cntx->datalen);
	memcpy(ubuf + cntx->datalen, input, update_len - cntx->datalen);

	if (NULL == (cmd = (sm3_user_update_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap(ubuf, (size_t)update_len);
		close(fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm3_update_rsp_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof(sm3_user_update_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM3_UPDATE;
	cmd->ctx_len = sizeof (SM3_CONTEXT);
	memcpy (cmd->ctx, (void*)ctx, sizeof (SM3_CONTEXT));
	cmd->size = update_len;

	if (0 != (ret = tpcm_transmit(cmd, cmd->uiCmdLength, rsp, &rspLen)))	goto out;

	if ((ret = tpcmRspRetCode (rsp))) goto out;

	if(tpcmReqLength(rsp) <= sizeof(sm3_update_rsp_st)){
		httc_util_pr_error ("Error response (length:%d < length:%ld)\n",
							 tpcmReqLength(rsp), (long int)sizeof(sm3_init_rsp_st));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if(tpcmReqLength(rsp) != (sizeof(sm3_update_rsp_st) + ntohl (rsp->ctx_len))){
		httc_util_pr_error ("Error response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_update_rsp_st) + ntohl (rsp->ctx_len), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if (ntohl (rsp->ctx_len) > sizeof (SM3_CONTEXT)){
		httc_util_pr_error("tcs sm3 context is not enough (%d < %ld)\n", ntohl (rsp->ctx_len), (long int)sizeof (SM3_CONTEXT));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	memcpy ((void*)ctx, (void*)rsp->ctx, ntohl (rsp->ctx_len));

	if (next_len){
		memcpy (cntx->data + cntx->datalen, input + ilen - next_len, next_len);
		cntx->datalen = next_len;
	}else{
		cntx->datalen = 0;
	}

out:
	munmap(ubuf, (size_t)update_len);
	close(fd);
	httc_free(cmd);
	return ret;
}

int tcs_sm3_finish (void* ctx, SM3_DIGEST output)
{
	int ret = 0;
	sm3_finish_req_st *req = NULL;
	sm3_finish_rsp_st *rsp = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_sm3_context_st *cntx = (tcs_sm3_context_st*)ctx;

	if (NULL == (req = (sm3_finish_req_st*)httc_malloc (sizeof (sm3_finish_req_st)))){
		httc_util_pr_error ("Req Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	if (NULL == (rsp = (sm3_finish_rsp_st*)httc_malloc (sizeof (sm3_finish_req_st)))){
		httc_util_pr_error ("Rsp Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}

	req->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	req->uiCmdLength = sizeof (sm3_finish_req_st);
	req->uiCmdCode = TPCM_ORD_SM3_FINISH;
	req->ctx_len = sizeof (SM3_CONTEXT);
	memcpy (&req->ctx, (void*)ctx, sizeof (tcs_sm3_context_st));

	if (0 != (ret = tpcm_transmit (req, sizeof (sm3_finish_req_st), rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if ((ret = tpcmRspRetCode (rsp))) goto out;

	if(tpcmReqLength(rsp) != sizeof(sm3_finish_rsp_st)){
		httc_util_pr_error ("Error response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_finish_rsp_st), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	memcpy (output, rsp->hash, DEFAULT_HASH_SIZE);

out:
	if (cntx) httc_free (cntx);
	if (req) httc_free (req);
	if (rsp) httc_free (rsp);
	return ret;
}

/** 运用SM3算法对指定数据计算摘要值 */
int tcs_sm3(const uint8_t *input, int ilen, uint8_t *output, int *olen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm3_req_st *cmd = NULL;
	sm3_rsp_st *rsp = NULL;

	if(ilen > TPCM_SM3_LIMIT){
		httc_util_pr_error("tcs sm3 input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if ((fd = open("/dev/httctcs", O_RDWR)) < 0)
	{
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if ((ubuf = mmap(NULL, (size_t)ilen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		httc_util_pr_error("######### Mmap Failed, size = %d\n", ilen);
		close(fd);
		return TSS_ERR_MAP;
	}
	memcpy(ubuf, input, ilen);
	if (NULL == (cmd = (sm3_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap(ubuf, (size_t)ilen);
		close(fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm3_rsp_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof(sm3_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM3;
	cmd->size = ilen;

	if (0 != (ret = tpcm_transmit(cmd, cmd->uiCmdLength, rsp, &rspLen)))
		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp))
	{
		httc_util_pr_error("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode(rsp)))
	{
		if (tpcmRspLength(rsp) != sizeof(sm3_rsp_st))
		{
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy(output, rsp->digest, DEFAULT_HASH_SIZE);
	}
	*olen = DEFAULT_HASH_SIZE;
out:
	munmap(ubuf, (size_t)ilen);
	close(fd);
	httc_free(cmd);
	return ret;
}

/** 运用SM3算法对指定数据摘要值进行验证 为奔图添加 */
/*
函数名: tcs_sm3_verify
功能: 通过可信根，使用SM3算法实现对数据的验证，并在可信根打印提示信息
参数: data : 验证的数据，
length : 验证数据长度（最大100字节），
verify : 待验证数据的sm3值，
size : sm3数据长度
返回值： 0 成功、其他失败
其他需求：可信根通过串口打印，data、verify、校验结果
*/
int tcs_sm3_verify(const uint8_t *data, uint32_t len, const uint8_t *verify, uint32_t size)
{
	int ret;
	int rspLen = ALLOC_SIZE / 2;
	sm3_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	int cmdLen = 0;
	uint32_t length = len;

	if (length > 100)
	{
		httc_util_pr_error("tcs sm3 verify input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}
	if (size != DEFAULT_HASH_SIZE)
	{
		httc_util_pr_error("tcs sm3 verify verify not correct\n");
		return TSS_ERR_BAD_DATA;
	}

	if (NULL == (cmd = (sm3_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	rsp = (tpcm_rsp_header_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmdLen = sizeof(tpcm_req_header_st);

	cmdLen += httc_insert_data((const char *)data, length, (void *)cmd + cmdLen);
	cmdLen += httc_insert_data((const char *)verify, DEFAULT_HASH_SIZE, (void *)cmd + cmdLen);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SM3_VERIFY);

	if (0 != (ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)))
		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp))
	{
		httc_util_pr_error("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

out:
	httc_free(cmd);
	return ret;
}
/** 运用SM2算法对指定数据的摘要值进行签名 */
int tcs_sm2_sign(uint8_t *privkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t *siglen)
{
	int ret;
	int rspLen = ALLOC_SIZE / 2;
	sm2_sign_e_req_st *cmd = NULL;
	sm2_sign_e_rsp_st *rsp = NULL;

	if (NULL == (cmd = (sm2_sign_e_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm2_sign_e_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(sizeof (sm2_sign_e_req_st));
	cmd->uiCmdCode = htonl(TPCM_ORD_SM2Sign);
	memcpy (cmd->privkey, privkey, SM2_PRIVATE_KEY_SIZE);
	memcpy (cmd->digest, digest, DEFAULT_HASH_SIZE );

	if (0 != (ret = tpcm_transmit (cmd, sizeof (sm2_sign_e_req_st), rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if (tpcmRspLength (rsp) != sizeof (sm2_sign_e_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if ((int)(*siglen) < DEFAULT_SIGNATURE_SIZE){
		httc_util_pr_error ("[%s:%d] siglen is not enough (%d < %d)\n",
				__func__, __LINE__, (int)*siglen, DEFAULT_SIGNATURE_SIZE);
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*siglen = DEFAULT_SIGNATURE_SIZE;
	memcpy (sig, rsp->sig, *siglen);

out:
	httc_free (cmd);
	return ret;

}

/** 运用SM2算法对指定数据的摘要值进行验签 */
int tcs_sm2_verify(uint8_t *pubkey, uint8_t *digest, uint32_t digest_len, uint8_t *sig, uint32_t siglen)
{

	int ret;
	int rspLen = ALLOC_SIZE / 2;
	sm2_verify_e_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (cmd = (sm2_verify_e_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	rsp = (tpcm_rsp_header_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(sizeof (sm2_verify_e_req_st));
	cmd->uiCmdCode = htonl(TPCM_ORD_SM2Verify);
	memcpy (cmd->pubkey, pubkey, SM2_PUBLIC_KEY_SIZE);
	memcpy (cmd->digest, digest, DEFAULT_HASH_SIZE );
	memcpy (cmd->sig, sig, siglen);

	if (0 != (ret = tpcm_transmit (cmd, sizeof (sm2_verify_e_req_st), rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if (tpcmRspLength (rsp) != sizeof (tpcm_rsp_header_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

out:
	httc_free (cmd);
	return ret;
}

/** 运用SM2算法对指定数据的摘要值进行验签 为奔图添加*/

int tcs_sm2_verify_b(const uint8_t *pubkey,
					 uint32_t keylen,
					 const uint8_t *hash,
					 uint32_t hashlen,
					 const uint8_t *sign,
					 uint32_t signlen)
{

	int ret;
	int rspLen = ALLOC_SIZE / 2;
	sm2_verify_b_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (cmd = (sm2_verify_b_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	rsp = (tpcm_rsp_header_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(sizeof(sm2_verify_b_req_st));
	cmd->uiCmdCode = htonl(TPCM_ORD_SM2VerifyB);

	cmd->publen = htonl(SM2_PUBLIC_KEY_SIZE);
	cmd->diglen = htonl(DEFAULT_HASH_SIZE);
	cmd->siglen = htonl(SM2_SIGNATURE_SIZE);
	memcpy(cmd->pubkey, pubkey, SM2_PUBLIC_KEY_SIZE);
	memcpy(cmd->digest, hash, DEFAULT_HASH_SIZE);
	memcpy(cmd->sig, sign, SM2_SIGNATURE_SIZE);

	if (0 != (ret = tpcm_transmit(cmd, sizeof(sm2_verify_b_req_st), rsp, &rspLen)))
		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp))
	{
		httc_util_pr_error("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode(rsp)))
		goto out;

	if (tpcmRspLength(rsp) != sizeof(tpcm_rsp_header_st))
	{
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

out:
	httc_free(cmd);
	return ret;
}
/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行签名 */
int tcs_sm2_sign_e(uint8_t *privkey, uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t *siglen)
{

	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm2_sign_req_st *cmd = NULL;
	sm2_sign_rsp_st *rsp = NULL;

	if(datalen > TPCM_SM2_SIGN_LIMIT){
		httc_util_pr_error("tcs sm2 sign e input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if ((fd = open("/dev/httctcs", O_RDWR)) < 0)
	{
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if ((ubuf = mmap(NULL, (size_t)datalen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		httc_util_pr_error("######### Mmap Failed, size = %d\n", datalen);
		close(fd);
		return TSS_ERR_MAP;
	}
	memcpy(ubuf, data, datalen);

	if (NULL == (cmd = (sm2_sign_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap(ubuf, (size_t)datalen);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm2_sign_rsp_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof(sm2_sign_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM2SignE;
	memcpy(cmd->privkey, privkey, SM2_PRIVATE_KEY_SIZE);
	memcpy(cmd->pubkey, pubkey, SM2_PUBLIC_KEY_SIZE);
	cmd->size = datalen;

	if (0 != (ret = tpcm_transmit(cmd, sizeof(sm2_sign_req_st), rsp, &rspLen)))
		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp))
	{
		httc_util_pr_error("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode(rsp)))
		goto out;

	if (tpcmRspLength(rsp) != sizeof(sm2_sign_rsp_st))
	{
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if ((int)(*siglen) < DEFAULT_SIGNATURE_SIZE)
	{
		httc_util_pr_error("[%s:%d] sig is not enough (%d < %d)\n",
			   __func__, __LINE__, (int)*siglen, (int)DEFAULT_SIGNATURE_SIZE);
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*siglen = DEFAULT_SIGNATURE_SIZE;
	memcpy(sig, rsp->sig, *siglen);

out:
	munmap(ubuf, (size_t)datalen);
	close(fd);
	httc_free(cmd);
	return ret;
}

/** 运用SM2算法对指定数据进行签名
	TPCM对原始数据先进行压缩，对压缩后数据进行验签  */
int tcs_sm2_verify_e(uint8_t *pubkey, uint8_t *data, uint32_t datalen, uint8_t *sig, uint32_t siglen)
{

	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm2_verify_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(datalen > TPCM_SM2_SIGN_LIMIT){
		httc_util_pr_error("tcs sm2 verify e input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if ((fd = open("/dev/httctcs", O_RDWR)) < 0)
	{
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if ((ubuf = mmap(NULL, (size_t)datalen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
	{
		httc_util_pr_error("######### Mmap Failed, size = %d\n", datalen);
		close(fd);
		return TSS_ERR_MAP;
	}
	memcpy(ubuf, data, datalen);

	if (NULL == (cmd = (sm2_verify_req_st *)httc_malloc(ALLOC_SIZE)))
	{
		httc_util_pr_error("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap(ubuf, (size_t)datalen);
		return TSS_ERR_NOMEM;
	}

	rsp = (tpcm_rsp_header_st *)((void *)cmd + ALLOC_SIZE / 2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof(sm2_verify_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM2VerifyE;
	memcpy(cmd->pubkey, pubkey, SM2_PUBLIC_KEY_SIZE);
	memcpy(cmd->sig, sig, siglen);
	cmd->size = datalen;

	if (0 != (ret = tpcm_transmit(cmd, sizeof(sm2_verify_req_st), rsp, &rspLen)))
		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp))
	{
		httc_util_pr_error("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	if (0 != (ret = tpcmRspRetCode(rsp)))
		goto out;

	if (tpcmRspLength(rsp) != sizeof(tpcm_rsp_header_st))
	{
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

out:
	munmap(ubuf, (size_t)datalen);
	close(fd);
	httc_free(cmd);
	return ret;
}


int tcs_sm4_ecb_mode_encrypt(uint8_t *key, uint32_t mode, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	int maplen = datalen + 16;	/** pad */
	sm4_encrypt_req_st *cmd = NULL;
	sm4_encrypt_rsp_st *rsp = NULL;

	if((fd = open("/dev/httctcs", O_RDWR)) < 0){
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if((ubuf = mmap (NULL, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		httc_util_pr_error("######### Mmap Failed, size = %d\n", maplen);
		close (fd);
		return TSS_ERR_MAP;
	}
	memcpy (ubuf, data, datalen);

	if (NULL == (cmd = (sm4_encrypt_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap (ubuf, (size_t)maplen);
		close (fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm4_encrypt_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof (sm4_encrypt_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM4Encrypt;
	cmd->mode = mode;
	memcpy (cmd->key, key, SM4_KEY_SIZE);
	memset(cmd->iv, 0, SM4_IV_SIZE);
	cmd->size = datalen;
	if (0 != (ret = tpcm_transmit (cmd, cmd->uiCmdLength, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if(tpcmRspLength (rsp) != sizeof (sm4_encrypt_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if ((int)(*bloblen) < NTOHL (rsp->size)){
		httc_util_pr_error ("[%s:%d] blob is not enough (%d < %d)\n",
				__func__, __LINE__, (int)*bloblen, (int)NTOHL (rsp->size));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*bloblen = htonl(rsp->size);
	memcpy (blob, ubuf, *bloblen);

out:
	munmap (ubuf, (size_t)maplen);
	close (fd);
	httc_free (cmd);
	return ret;
}

int tcs_sm4_ecb_encrypt(uint8_t *key, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
 	return tcs_sm4_ecb_mode_encrypt(key, 1, data,  datalen,  blob,  bloblen);
}

int tcs_sm4_ecb_mode_decrypt(uint8_t *key, uint32_t mode, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm4_decrypt_req_st *cmd = NULL;
	sm4_decrypt_rsp_st *rsp = NULL;

	if((fd = open("/dev/httctcs", O_RDWR)) < 0){
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if((ubuf = mmap (NULL, datalen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		httc_util_pr_error("######### Mmap Failed, size = %d\n", datalen);
		close (fd);
		return TSS_ERR_MAP;
	}
	memcpy (ubuf, data, datalen);

	if (NULL == (cmd = (sm4_decrypt_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap (ubuf, (size_t)datalen);
		close (fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm4_decrypt_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof (sm4_decrypt_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM4Decrypt;
	cmd->mode = mode;
	memcpy (cmd->key, key, SM4_KEY_SIZE);
	memset(cmd->iv, 0, SM4_IV_SIZE);
	cmd->size = datalen;

	if (0 != (ret = tpcm_transmit (cmd, cmd->uiCmdLength, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;
	if(tpcmRspLength (rsp) != sizeof (sm4_decrypt_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if ((int)(*bloblen) < NTOHL (rsp->size)){
		httc_util_pr_error ("[%s:%d] blob is not enough (%d < %d)\n",
				__func__, __LINE__, (int)*bloblen, (int)NTOHL (rsp->size));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}

	*bloblen = htonl(rsp->size);

	memcpy (blob, ubuf, *bloblen);
	//httc_util_pr_error("------*bloblen = 0x%x, rsp->size = 0x%x--------\n", *bloblen, rsp->size);
        //httc_util_dump_hex("decrypt ubuf data : ",  ubuf,  *bloblen);

out:
	munmap (ubuf, (size_t)datalen);
	close (fd);
	httc_free (cmd);
	return ret;
}

int tcs_sm4_ecb_decrypt(uint8_t *key,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	return tcs_sm4_ecb_mode_decrypt( key, 1,  data,  datalen,  blob,  bloblen);
}


/** 运用SM4算法对指定数据进行加密，key为明文密钥 */
int tcs_util_sm4_cbc_encrypt(uint8_t *key, uint8_t *iv, uint32_t mode,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	int maplen = datalen + 16;	/** pad */
	sm4_encrypt_req_st *cmd = NULL;
	sm4_encrypt_rsp_st *rsp = NULL;

	if((fd = open("/dev/httctcs", O_RDWR)) < 0){
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if((ubuf = mmap (NULL, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		httc_util_pr_error("######### Mmap Failed, size = %d\n", maplen);
		close (fd);
		return TSS_ERR_MAP;
	}
	memcpy (ubuf, data, datalen);

	if (NULL == (cmd = (sm4_encrypt_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap (ubuf, (size_t)maplen);
		close (fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm4_encrypt_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof (sm4_encrypt_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM4Encrypt;
	cmd->mode = mode;
	memcpy (cmd->key, key, SM4_KEY_SIZE);
	memcpy(cmd->iv, iv, SM4_IV_SIZE);
	cmd->size = datalen;
//httc_util_pr_error("--------%s, %d-------\n", __func__, __LINE__);
	if (0 != (ret = tpcm_transmit (cmd, cmd->uiCmdLength, rsp, &rspLen)))		goto out;
//httc_util_pr_error("--------%s, %d-------\n", __func__, __LINE__);
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if(tpcmRspLength (rsp) != sizeof (sm4_encrypt_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if ((int)(*bloblen) < NTOHL (rsp->size)){
		httc_util_pr_error ("[%s:%d] blob is not enough (%d < %d)\n",
				__func__, __LINE__, (int)*bloblen, (int)NTOHL (rsp->size));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}
	*bloblen = htonl(rsp->size);
	memcpy (blob, ubuf, *bloblen);

out:
	munmap (ubuf, (size_t)maplen);
	close (fd);
	httc_free (cmd);
	return ret;
}

static int cbc_seg_limit = 128 * 1024 * 1024;

int tcs_sm4_cbc_mode_encrypt(uint8_t *key, uint8_t *iv, uint32_t mode, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret = 0;
	int i = 0;
	uint8_t *pdata = NULL;
	uint8_t *blob_out = NULL;
	uint32_t blob_len  = cbc_seg_limit + SM4_IV_SIZE;
	uint32_t blob_total_len = 0;
	uint32_t size = datalen;
	unsigned char seg_iv[SM4_IV_SIZE] = {0};
	int seg_num = size/cbc_seg_limit + ((size%cbc_seg_limit  != 0) ? 1 : 0);

	memcpy(seg_iv, iv, SM4_IV_SIZE);
	memset(blob, 0, *bloblen);
	for(i = 0; i < seg_num; i++){
		 pdata = data + i * cbc_seg_limit;
		 blob_out =  blob + i * cbc_seg_limit + i * SM4_IV_SIZE;
		if(size > cbc_seg_limit){
			ret = tcs_util_sm4_cbc_encrypt(key,  seg_iv, mode, pdata,  cbc_seg_limit,  blob_out,  &blob_len);
			if(ret){
				httc_util_pr_error("[%s:%d]---tcs_util_sm4_cbc_encrypt cbc_seg_limit error---\n",  __func__, __LINE__);
				goto out;
			}
			memset(seg_iv, 0, SM4_IV_SIZE);
			memcpy(seg_iv, blob_out + blob_len - (2 * SM4_IV_SIZE),  SM4_IV_SIZE);
			//httc_util_dump_hex("encrypt iv : ", seg_iv , SM4_IV_SIZE);
			blob_total_len += blob_len;
			size -= cbc_seg_limit;
		}
		else{
			if(size > 0){
				ret = tcs_util_sm4_cbc_encrypt(key,  seg_iv, mode, pdata,  size,  blob_out,  &blob_len);
				if(ret){
					httc_util_pr_error("---tcs_util_sm4_cbc_encrypt rest error---\n");
					goto out;
				}
				blob_total_len += blob_len;
			}
		}

	}

	*bloblen = blob_total_len;

out:
	 return ret;
}


int tcs_sm4_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	return tcs_sm4_cbc_mode_encrypt( key,  iv,  2,  data,  datalen,  blob,  bloblen);
}

/** 运用SM4算法对指定数据进行解密，key为明文密钥 */
int tcs_util_sm4_cbc_decrypt(uint8_t *key, uint8_t *iv, uint32_t mode,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret;
	int fd = 0;
	int rspLen = ALLOC_SIZE / 2;
	uint8_t *ubuf = NULL;
	sm4_decrypt_req_st *cmd = NULL;
	sm4_decrypt_rsp_st *rsp = NULL;

	if((fd = open("/dev/httctcs", O_RDWR)) < 0){
		httc_util_pr_error("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if((ubuf = mmap (NULL, datalen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		httc_util_pr_error("######### Mmap Failed, size = %d\n", datalen);
		close (fd);
		return TSS_ERR_MAP;
	}
	memcpy (ubuf, data, datalen);

	if (NULL == (cmd = (sm4_decrypt_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		munmap (ubuf, (size_t)datalen);
		close (fd);
		return TSS_ERR_NOMEM;
	}

	rsp = (sm4_decrypt_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = sizeof (sm4_decrypt_req_st);
	cmd->uiCmdCode = TPCM_ORD_SM4Decrypt;
	cmd->mode = mode;
	memcpy (cmd->key, key, SM4_KEY_SIZE);
	memcpy(cmd->iv, iv, SM4_IV_SIZE);
	cmd->size = datalen;

	if (0 != (ret = tpcm_transmit (cmd, cmd->uiCmdLength, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;
	if(tpcmRspLength (rsp) != sizeof (sm4_decrypt_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if ((int)(*bloblen) < NTOHL (rsp->size)){
		httc_util_pr_error ("[%s:%d] blob is not enough (%d < %d)\n",
				__func__, __LINE__, (int)*bloblen, (int)NTOHL (rsp->size));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto out;
	}

	*bloblen = htonl(rsp->size);

	memcpy (blob, ubuf, *bloblen);
	//httc_util_pr_error("------*bloblen = 0x%x, rsp->size = 0x%x--------\n", *bloblen, rsp->size);
        //httc_util_dump_hex("decrypt ubuf data : ",  ubuf,  *bloblen);

out:
	munmap (ubuf, (size_t)datalen);
	close (fd);
	httc_free (cmd);
	return ret;
}



int tcs_sm4_cbc_mode_decrypt(uint8_t *key, uint8_t *iv, uint32_t mode,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	int ret = 0;
	int i = 0;
	uint8_t *pdata = NULL;
	uint8_t *blob_out = NULL;
	uint32_t blob_len  =  cbc_seg_limit ;
	uint32_t blob_total_len = 0;
	uint32_t size = datalen;
	unsigned char seg_iv[SM4_IV_SIZE] = {0};
	unsigned char util_iv[SM4_IV_SIZE] = {0};
	int seg_num = size/(cbc_seg_limit  +  SM4_IV_SIZE)+ ((size%(cbc_seg_limit + SM4_IV_SIZE)  != 0) ? 1 : 0);

	memcpy(seg_iv, iv,  SM4_IV_SIZE);
	memset(blob, 0, *bloblen);
	for(i = 0; i < seg_num; i++){
		pdata = data + i * cbc_seg_limit + i * SM4_IV_SIZE;
		blob_out = blob + i * cbc_seg_limit;

		if(i != (seg_num -1))
			memcpy(util_iv, pdata + cbc_seg_limit -SM4_IV_SIZE, SM4_IV_SIZE );
		else
			memcpy(util_iv, pdata,  SM4_IV_SIZE );
		if(size > cbc_seg_limit ){
			ret = tcs_util_sm4_cbc_decrypt(key,  seg_iv,  mode, pdata,  cbc_seg_limit + SM4_IV_SIZE ,  blob_out,  &blob_len);
			if(ret){
				httc_util_pr_error("[%s:%d]---tcs_util_sm4_cbc_decrypt cbc_seg_limit error---\n",  __func__, __LINE__);
				goto out;
			}
			memset(seg_iv, 0, SM4_IV_SIZE);
			memcpy(seg_iv, util_iv,  SM4_IV_SIZE);
			//httc_util_dump_hex("decrypt iv : ", seg_iv , SM4_IV_SIZE);
			blob_total_len += blob_len;
			size -= (cbc_seg_limit + SM4_IV_SIZE);
		}else{

		       if(size > 0){
				ret = tcs_util_sm4_cbc_decrypt(key,  seg_iv, mode,  pdata,  size,  blob_out,  &blob_len);
				if(ret){
					httc_util_pr_error("---tcs_util_sm4_cbc_decrypt rest error---\n");
					goto out;
				}
				blob_total_len += blob_len;
		       }
		}
    }

	*bloblen = blob_total_len;
out:
	return ret;
}

int tcs_sm4_cbc_decrypt(uint8_t *key, uint8_t *iv,  uint8_t *data, uint32_t datalen, uint8_t *blob, uint32_t *bloblen)
{
	return  tcs_sm4_cbc_mode_decrypt(key,  iv,  2,   data,  datalen,  blob,  bloblen);
}

int tcs_random (uint8_t *data, uint32_t size)
{
	int ret = 0;
	int pos = 0;
	uint32_t actual_size = 0;

	TCM_setlog(1);
	TCM_Open();
	while(size > 0){
		pos += actual_size;
		ret = TCM_GetRandom(size,  data + pos, &actual_size);
	        if (0 != ret) {
			httc_util_pr_error("Error %s from TCM_GetRandom.\n",
			       TCM_GetErrMsg(ret));
			exit (ret);
	        }
		size -= actual_size;
	}
	TCM_Close();

	return ret;
}

int tcs_hash_sign(uint32_t index, uint8_t *digest, uint8_t *sig)
{
	int ret;
	int rspLen = ALLOC_SIZE / 2;
	hash_sign_req_st *cmd = NULL;
	hash_sign_rsp_st *rsp = NULL;

	if ( (digest == NULL) || (sig == NULL) || ( index < 0 ) )	return TSS_ERR_PARAMETER;

	if (NULL == (cmd = (hash_sign_req_st *)httc_malloc (ALLOC_SIZE))){
		httc_util_pr_error ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	rsp = (hash_sign_rsp_st*)((void*)cmd + ALLOC_SIZE/2);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(sizeof (hash_sign_req_st));
	cmd->uiCmdCode = htonl(TPCM_ORD_HashSign);
	cmd->index = htonl(index);
	memcpy (cmd->digest, digest, DEFAULT_HASH_SIZE );

	if (0 != (ret = tpcm_transmit (cmd, sizeof (hash_sign_req_st), rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("[%s:%d] Invalid tpcm rsp tag(0x%02X)\n", __func__, __LINE__, tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if (tpcmRspLength (rsp) != sizeof (hash_sign_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	memcpy (sig, rsp->sig, DEFAULT_SIGNATURE_SIZE);

out:
	httc_free (cmd);
	return ret;
}




