#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "uutils.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_constant.h"
#include "tcs_policy.h"


#pragma pack(push, 1)
typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_set_global_control_policy;

typedef struct{
	RESPONSE_HEADER;
	uint8_t  uaData[0];
}tcs_rsp_get_global_control_policy;

typedef struct{
	COMMAND_HEADER;
	uint64_t Nonce;
}tcs_req_get_policy_report;

typedef struct{
	RESPONSE_HEADER;
	struct policy_report report;
}tcs_rsp_get_policy_report;

typedef struct tcs_set_measure_ctrl_switch_req{
	COMMAND_HEADER;
	struct measure_ctrl_switch ctrl;
	//struct tpcm_data uid;
	//struct tpcm_auth auth;
}tpcm_set_measure_ctrl_switch_req_st;

#pragma pack(pop)


int tcs_set_global_control_policy(struct global_control_policy_update *data,		const char *uid,
														int auth_type, int auth_length,unsigned char *auth){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t ali_len = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_set_global_control_policy *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(data == NULL) return TSS_ERR_PARAMETER;

	if(NULL == (cmd = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_set_global_control_policy *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	
	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(auth_type,auth_length,auth,req->uaData + op);
	op += ali_len;	
	memcpy(req->uaData + op,data,sizeof(struct global_control_policy_update));
	op += sizeof(struct global_control_policy_update);

	cmdlen = op + sizeof(tcs_req_set_global_control_policy);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetGlobalControlPolicy);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);
		
out:
	if(cmd) httc_free(cmd);
	return ret;
}
		

int tcs_get_global_control_policy(struct global_control_policy *policy){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_global_control_policy *rsp = NULL;

	if(policy == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_global_control_policy *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetGlobalControlPolicy);
	
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

	if (tpcmRspLength (rsp) == (sizeof (tcs_rsp_get_global_control_policy) + sizeof(struct global_control_policy))){
		memcpy(policy,rsp->uaData,sizeof(struct global_control_policy));
	}
	else{
		httc_util_pr_error ("Result is not enough (%ld < %ld)\n",
										(long int)(tpcmRspLength (rsp) - sizeof (tcs_rsp_get_global_control_policy)), 
										(long int)sizeof(struct global_control_policy));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_get_policy_report(struct policy_report *policy_report,uint64_t nonce){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_get_policy_report *req = NULL;
	tcs_rsp_get_policy_report *rsp = NULL;

	if(policy_report == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_get_policy_report *)cmd;
	rsp = (tcs_rsp_get_policy_report *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	req->Nonce = htonll(nonce);

	cmdlen = sizeof(tcs_req_get_policy_report);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetPolicyReport);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if(tpcmRspRetCode(rsp)){		
		ret = tpcmRspRetCode(rsp);
		goto out;	
	}
	

	if (tpcmRspLength (rsp) == sizeof (tcs_rsp_get_policy_report)){
		memcpy(policy_report,&rsp->report,sizeof(struct policy_report));
	}
	else{
		httc_util_pr_error ("mresult is not enough (%d < %ld)\n", 
										tpcmRspLength (rsp), 
										(long int)sizeof(struct policy_report));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_set_measure_control_switch (struct measure_ctrl_switch *ctrl,
					const char *uid, int auth_type, int auth_length, unsigned char *auth)
{
	int ret = 0;
	int ops = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_set_measure_ctrl_switch_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	int uid_len = 0;
	int auth_len = 0;

	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;

	cmdLen = sizeof (tpcm_set_measure_ctrl_switch_req_st)
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (buffer = httc_malloc (cmdLen + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_set_measure_ctrl_switch_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + cmdLen);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetSignMeasureSwitch);
	memcpy (&cmd->ctrl, ctrl, sizeof (struct measure_ctrl_switch));
	ops = sizeof (tpcm_set_measure_ctrl_switch_req_st);
	ops += httc_insert_uid_align4 (uid, (void*)cmd + ops);
	ops += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + ops);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	if (tpcmRspLength (rsp) != sizeof (tpcm_rsp_header_st)){
		httc_util_pr_error ("Invalid tpcm response.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer) httc_free (buffer);
	return ret;
}

