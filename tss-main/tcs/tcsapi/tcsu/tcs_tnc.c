#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "uutils.h"
#include "convert.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_tnc.h"
#include "tcs_tnc_def.h"
#include "tcs_error.h"
#include "tcs_constant.h"

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_update_tnc_policy;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiTnclength;
	uint8_t  uaData[0];
}tcs_rsp_get_tnc_policy;

#pragma pack(pop)

int tcs_update_tnc_policy(struct tnc_policy_update *update, const char *uid,int cert_type,
																int auth_length,unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t length = 0;
	uint32_t ali_len = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_update_tnc_policy *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if(update == NULL) return TSS_ERR_PARAMETER;
	
	length = sizeof(struct tnc_policy_update) + ntohl(update->be_data_length) 
			+ sizeof(tcs_req_update_tnc_policy) +  MAX_CMD_AUTH_SIZE + rspLen;

	if(NULL == (cmd = httc_malloc(length))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_update_tnc_policy *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));
	
	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaData + op);
	op += ali_len;	
	memcpy(req->uaData + op,update,sizeof(struct tnc_policy_update));
	op += sizeof(struct tnc_policy_update);
	memcpy(req->uaData + op,update->policy,	ntohl(update->be_data_length));
	op += ntohl(update->be_data_length);
	

	cmdlen = op + sizeof(tcs_req_update_tnc_policy);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_UpdateTncPolicy);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);		
out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_get_tnc_policy(struct tnc_policy **tnc_policy,int *length){

	int ret = 0;
	int tnc_length = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;	
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_tnc_policy *rsp = NULL;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_tnc_policy *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdlen = sizeof(tpcm_req_header_st);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetTncPolicy);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if(tpcmRspRetCode(rsp)){		
		ret = tpcmRspRetCode(rsp);
		goto out;	
	}

	if (tpcmRspLength (rsp) == sizeof(tcs_rsp_get_tnc_policy) + ntohl(rsp->uiTnclength)&&
	 (CMD_DEFAULT_ALLOC_SIZE/2) > sizeof(tcs_rsp_get_tnc_policy) + ntohl(rsp->uiTnclength)){
		
			tnc_length = ntohl(rsp->uiTnclength);		
			if (NULL == (*tnc_policy = (struct tnc_policy *)httc_malloc (tnc_length))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TSS_ERR_NOMEM;
				*length = 0;
				goto out;
			}
			memcpy(*tnc_policy,rsp->uaData,tnc_length);
			*length = tnc_length;		
	}
	else{
		httc_util_pr_error ("Result length error [rsplength:%d Tnclength:%d structlength:%ld]\n",
										tpcmRspLength (rsp),ntohl(rsp->uiTnclength),
										(long int)sizeof(tcs_rsp_get_tnc_policy));
		*length = 0;
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}	
out:
	if(cmd) httc_free(cmd);
	return ret;
}

