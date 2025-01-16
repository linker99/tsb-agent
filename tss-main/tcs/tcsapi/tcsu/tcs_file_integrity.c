#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "uutils.h"
#include "tcs_auth.h"
#include "tcs_tpcm.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tpcm_command.h"
#include "tcs_config.h"
#include "tcs_attest_def.h"
#include "transmit.h"
#include "tcs_file_integrity.h"
#include "tcs_util_policy_update.h"
#include "crypto/sm/sm3.h"

#pragma pack(push, 1)

typedef struct get_progress_reference_size_rsp{
	RESPONSE_HEADER;
	int size;
}get_progress_reference_size_rsp_st; 

typedef struct get_progress_reference_user_req{
	COMMAND_HEADER;
	int size;
}get_progress_reference_user_req_st; 

typedef struct get_progress_reference_rsp{
	RESPONSE_HEADER;
	uint32_t num;
	uint8_t reference[0];
}get_progress_reference_rsp_st; 

typedef struct{
	RESPONSE_HEADER;
	uint32_t value;
}get_u32_value_rsp_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiMrLen;		/** Measure result length */
	uint8_t  uaMresult[0];	/** Measure result */
}imeasure_rsp_st;

typedef struct {
	COMMAND_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}update_file_integrity_digest_req_st;

typedef struct {
	COMMAND_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}update_cirtical_file_integrity_digest_req_st;


typedef struct {
	RESPONSE_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}get_file_integrity_digest_rsp_st;

#pragma pack(pop)


int tcs_update_file_integrity (struct file_integrity_update *references,
		const char *uid, int auth_type, int auth_length, unsigned char *auth)
	{
		int ret = 0;
		uint64_t counter = 0;
		/*Check policy*/
		if( 0 != (ret = tcs_util_check_file_integrity_update (references))) {
			httc_util_pr_error ("tcs_util_check_file_integrity_update error: %d(0x%x)\n", ret, ret);
			return ret;
		}
		counter = ntohll(references->be_replay_counter);
		if( 0 != (ret = tcs_util_write_policy_version (POLICY_TYPE_FILE_INTEGRITY, counter))){
			httc_util_pr_error ("tcs_util_write_policy_version error: %d(0x%x)\n", ret, ret);
			return ret;
		}
	
		return TSS_SUCCESS; 
	}

int tcs_get_file_integrity_size (int *size)
{
	int ret = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_req_header_st *cmd = NULL;
	struct get_progress_reference_size_rsp *rsp = NULL;

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (struct get_progress_reference_size_rsp*)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (sizeof (tpcm_req_header_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_GetProgressReferenceSize);

	if (0 != (ret = tpcm_transmit (cmd, sizeof (tpcm_req_header_st), rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (struct get_progress_reference_size_rsp) != tpcmRspLength (rsp)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
		}
		*size = ntohl (rsp->size);
	}

out:
	if (cmd)	httc_free (cmd);
	return ret;
}
static char* tpcm_memcpy(void *dst, const void *src, int size)
{
	int i = 0;
	char *s = dst;
	char *pdst = dst;
	const char *psrc = src;
	while (i < size)
	{
		*(pdst + i) = *(psrc + i);
		i ++;
	}
	return s;
}

int tcs_get_file_integrity(struct file_integrity_item **references, uint32_t *num, int *length)
{
	int ret = 0;
	int fd = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	struct get_progress_reference_user_req *cmd = NULL;
	struct get_progress_reference_rsp *rsp = NULL;
	uint8_t *ubuf = NULL;

	if (0 != (ret = tcs_get_file_integrity_size (length))){
		httc_util_pr_error ("Error: get_file_integrity_size error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	if (*length == 0) {
		*num = 0;
		return TSS_SUCCESS;
	}

	if((fd = open("/dev/httctcs", O_RDWR)) < 0){
		httc_util_pr_error ("open httctcs fail\n");
		return TSS_ERR_DEV_OPEN;
	}

	if((ubuf = mmap (NULL, (size_t)*length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		httc_util_pr_error ("######### Mmap Failed, size = %d\n", (int)*length);
		close (fd);
		return TSS_ERR_MAP;
	}

	//httc_util_dump_hex ((uint8_t *)"ubuf", ubuf, *length);

	if (NULL == (cmd = (struct get_progress_reference_user_req *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		munmap (ubuf, (size_t)*length);
		close (fd);
		return TSS_ERR_NOMEM;
	}
	
	rsp = (struct get_progress_reference_rsp*)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;	
	cmd->uiCmdLength = sizeof (struct get_progress_reference_user_req);
	cmd->uiCmdCode = TPCM_ORD_GetProgressReference;
	cmd->size = *length;

	if (0 != (ret = tpcm_transmit (cmd, sizeof (struct get_progress_reference_user_req), rsp, &rspLen)))		goto out;

	//httc_util_dump_hex ((uint8_t *)"ubuf", ubuf, *length);
	if (0 == (ret = tpcmRspRetCode (rsp))){
		*num = ntohl (rsp->num);
		if (NULL == (*references = (struct file_integrity_item *)httc_malloc (*length))){
			httc_util_pr_error ("file_integrity Alloc error!\n");
			goto out;
		}
		tpcm_memcpy(*references, ubuf, *length);
	}

out:
	munmap (ubuf, (size_t)*length);
	close (fd);
	httc_free (cmd);
	return ret;
}

int tcs_get_file_integrity_valid_number (uint32_t *num)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_u32_value_rsp_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	rsp = (get_u32_value_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetProcessReferenceValidCount);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (get_u32_value_rsp_st) != tpcmRspLength (rsp)){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*num = ntohl (rsp->value);
	}
	
out:	
	if (buffer)	httc_free (buffer);
	//DEBUG (ret);
	return ret;
}

int tcs_get_file_integrity_total_number (uint32_t *num)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_u32_value_rsp_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	rsp = (get_u32_value_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetProcessReferenceTotalCount);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (get_u32_value_rsp_st) != tpcmRspLength (rsp)){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*num = ntohl (rsp->value);
	}
	
out:	
	if (buffer)	httc_free (buffer);
	//DEBUG (ret);
	return ret;
}

int tcs_get_file_integrity_modify_number_limit (uint32_t *num)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_u32_value_rsp_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	rsp = (get_u32_value_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetProcessReferenceModifyLimit);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (get_u32_value_rsp_st) != tpcmRspLength (rsp)){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*num = ntohl (rsp->value);
	}
	
out:	
	if (buffer)	httc_free (buffer);
	//DEBUG (ret);
	return ret;
}

int tcsk_integrity_measure_easy (
			uint8_t *imKey, uint32_t imKeyLen, uint32_t type,
			uint8_t *data, uint32_t dataLen, uint32_t *tpcmRes, uint32_t *mrLen, uint8_t *mresult)
{
	int ret = 0;
	int op = 0;
	int cmdAllocLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	uint8_t *cmd = NULL;
	imeasure_rsp_st *rsp = NULL;
	tpcm_req_header_st *req = NULL;

	cmdAllocLen = imKeyLen + dataLen + 128;

	if (NULL == (cmd = httc_malloc (cmdAllocLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (imeasure_rsp_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}
	
	op = sizeof (tpcm_req_header_st);
	
	/** Insert imKeyLen && imKey */
	*((uint32_t*)(cmd + op)) = imKeyLen;
	op += 4;
	memcpy (cmd + op, imKey, imKeyLen);
	op += imKeyLen;

	/** Insert im type */
	*((uint32_t*)(cmd + op)) = type;
	op += 4;	

	/** Insert dataLen && data */
	*((uint32_t*)(cmd + op)) = dataLen;
	op += 4;
	memcpy (cmd + op, data, dataLen);
	op += dataLen;

	/** Insert req header */
	req = (tpcm_req_header_st *)cmd;
	req->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	req->uiCmdLength = op;
	req->uiCmdCode = TPCM_ORD_InterceptMeasure;

	if (0 != (ret = tpcm_transmit (cmd, op, rsp, &rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);
	if (tpcmRspLength (rsp) > sizeof (tpcm_rsp_header_st)){
		if ((int)(*mrLen) < (int)(ntohl (rsp->uiMrLen))){
			httc_util_pr_error ("mresult is not enough (%d < %d)\n", *mrLen, ntohl (rsp->uiMrLen));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*mrLen = ntohl (rsp->uiMrLen);
		memcpy (mresult, rsp->uaMresult, *mrLen);
	}
	else{
		*mrLen = 0;
	}
	
out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	//DEBUG (ret);
	return ret;
}

/*
 *	更新文件完整性库hash
 */
int tcs_update_file_integrity_digest (unsigned char *digest ,unsigned int digest_len){

	int ret = 0;
	int cmdLen = sizeof(update_file_integrity_digest_req_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	update_file_integrity_digest_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(digest == NULL || digest_len != DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (update_file_integrity_digest_req_st *)buf;
	rsp = (tpcm_rsp_header_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	memcpy(cmd->hash,digest,DEFAULT_HASH_SIZE);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_UpdateFileintergrityDigest);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buf)	httc_free (buf);
	return ret;	
}

/*
 *	获取文件完整性库hash
 */
int tcs_get_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len){

	int ret = 0;
	int cmdLen = sizeof(tpcm_req_header_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_file_integrity_digest_rsp_st *rsp = NULL;

	if(digest == NULL || digest_len == NULL || *digest_len < DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buf;
	rsp = (get_file_integrity_digest_rsp_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetFileintergrityDigest);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	
	if(tpcmReqLength(rsp) != sizeof(get_file_integrity_digest_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		httc_util_pr_error ("Error response exp_length:%ld act_length:%d\n",
							(long int)sizeof(get_file_integrity_digest_rsp_st), tpcmReqLength(rsp));
		goto out;
	}
	memcpy(digest,rsp->hash,DEFAULT_HASH_SIZE);
	*digest_len = DEFAULT_HASH_SIZE;
	
	ret = tpcmRspRetCode (rsp);

out:
	if (buf)	httc_free (buf);
	return ret;	

}


/** 更新关键文件完整性基准库 */
int tcs_update_critical_file_integrity_to_tpcm(
		struct file_integrity_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth)
{
	/**	
	struct file_integrity_update_req{
		RESPONSE_HEADER;
		struct tpcm_data uid;
		struct tpcm_auth auth;
		uint32_t type;
		struct file_integrity_update ref;
	};
*/
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	struct file_integrity_update *ref = NULL;
	int size = 0;
	int ref_size = 0;
	int uid_len = 0;
	int auth_len = 0;
	int default_hash_len = 1;

	if (ntohl (references->be_size) != sizeof (struct file_integrity_update)){
		return TSS_ERR_PARAMETER;
	}
	if ((!auth && auth_length) || (auth && (auth_length <= 0)))	return TSS_ERR_PARAMETER;
	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;
	
	ref_size = ntohl (references->be_size) + ntohl (references->be_data_length);
	size = sizeof (tpcm_req_header_st) + ref_size
			+ sizeof (struct tpcm_data) + uid_len + sizeof (struct tpcm_auth) + auth_len + default_hash_len;

	if (NULL == (cmd = httc_malloc (size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tpcm_rsp_header_st *)((void*)cmd + size + 1);
	cmdLen = sizeof (tpcm_req_header_st);

	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + cmdLen);

	/** Insert hash */
	*(uint32_t *)((void *)cmd + cmdLen) = 0;
	cmdLen += 4;
	
	/** Insert reference type */
	*(uint32_t *)((void*)cmd + cmdLen) = htonl (RT_WHILELIST);
	cmdLen += 4;
	
	/** Insert references */
	ref = (struct file_integrity_update *)((void*)cmd + cmdLen);
	memcpy (ref, references, ref_size);
	cmdLen += ref_size;

	/** Insert cmd header */
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_UpdateCriticalFileIntergrity);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	ret = tpcmRspRetCode (rsp);
out:
	if (cmd)	httc_free (cmd);
	return ret;
}



/** 更新关键文件完整性基准库 */
int tcs_update_critical_file_integrity(
		struct file_integrity_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth){
	return tcs_update_critical_file_integrity_to_tpcm (references, uid, auth_type, auth_length, auth);
}


/** 获取关键文件完整性基准库摘要值 */
int tcs_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len)
{
	int ret = 0;
	int cmdLen = sizeof(tpcm_req_header_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_file_integrity_digest_rsp_st *rsp = NULL;

	if(digest == NULL || digest_len == NULL || *digest_len < DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buf;
	rsp = (get_file_integrity_digest_rsp_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetCriticalFileIntergrityDigest);
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if ((ret = tpcmRspRetCode (rsp)))	goto out;
	
	if(tpcmReqLength(rsp) != sizeof(get_file_integrity_digest_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		httc_util_pr_error ("Error response exp_length:%ld act_length:%d\n",
							(long int)sizeof(get_file_integrity_digest_rsp_st), tpcmReqLength(rsp));
		goto out;
	}
	memcpy(digest,rsp->hash,DEFAULT_HASH_SIZE);
	*digest_len = DEFAULT_HASH_SIZE;
	
out:
	if (buf)	httc_free (buf);
	return ret;	

}

/*
 *	更新关键文件完整性库hash
 */
int tcs_update_critical_file_integrity_digest (unsigned char *digest ,unsigned int digest_len)
{

	int ret = 0;
	int cmdLen = sizeof(update_cirtical_file_integrity_digest_req_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	update_cirtical_file_integrity_digest_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(digest == NULL || digest_len != DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (update_cirtical_file_integrity_digest_req_st *)buf;
	rsp = (tpcm_rsp_header_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	memcpy(cmd->hash,digest,DEFAULT_HASH_SIZE);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_UpdateCriticalFileintergrityDigest);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buf)	httc_free (buf);
	return ret;	

}


