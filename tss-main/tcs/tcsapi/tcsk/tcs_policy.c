#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_constant.h"
#include "tcs_policy.h"
#include "tcs_policy_mgmt.h"

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

#pragma pack(pop)

int tcs_ioctl_set_control_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	struct global_control_policy policy;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);	
	if (0 == (tpcmRspRetCode(rsp)) && !ret){
		if (0 == (ret = tcs_get_global_control_policy (&policy)))
			ret = tcs_util_set_global_control_policy (&policy);
	}
		
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

int tcs_ioctl_set_measure_control_switch (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	struct global_control_policy policy;
	uint8_t *cmd = NULL;
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);		
	if (0 == (tpcmRspRetCode(rsp)) && !ret){
		if (0 == (ret = tcs_get_global_control_policy (&policy)))
			ret = tcs_util_set_global_control_policy (&policy);
	}
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

int tcs_set_global_control_policy(struct global_control_policy_update *data,const char *uid,
													int auth_type, int auth_length,unsigned char *auth){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t ali_len = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_set_global_control_policy *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(data == NULL) return TSS_ERR_PARAMETER;

	if(NULL == (cmd = tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_set_global_control_policy *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(auth_type,auth_length,auth,req->uaData + op);
	op += ali_len;		
	tpcm_memcpy(req->uaData + op,data,sizeof(struct global_control_policy_update));
	op += sizeof(struct global_control_policy_update);

	cmdlen = op + sizeof(tcs_req_set_global_control_policy);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetGlobalControlPolicy);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);
		
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

EXPORT_SYMBOL(tcs_set_global_control_policy);	

int tcs_get_global_control_policy(struct global_control_policy *policy){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_global_control_policy *rsp = NULL;

	if(policy == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_global_control_policy *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetGlobalControlPolicy);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if((ret = tpcmRspRetCode(rsp)))	goto out;

	if (tpcmRspLength (rsp) == (sizeof (tcs_rsp_get_global_control_policy) + sizeof(struct global_control_policy))){
		tpcm_memcpy(policy,rsp->uaData,sizeof(struct global_control_policy));
	}
	else{
		httc_util_pr_error ("hter response length (%ld < %ld)\n",
										tpcmRspLength (rsp) - (long int)sizeof (tcs_rsp_get_global_control_policy), 
										(long int)sizeof(struct global_control_policy));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

EXPORT_SYMBOL(tcs_get_global_control_policy);

int tcs_get_policy_report(struct policy_report *policy_report,uint64_t nonce){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_get_policy_report *req = NULL;
	tcs_rsp_get_policy_report *rsp = NULL;
	uint64_t nnonce = 0;

	if(policy_report == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_get_policy_report *)cmd;
	rsp = (tcs_rsp_get_policy_report *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	nnonce = htonll(nonce);
	tpcm_memcpy(&(req->Nonce),&nnonce, sizeof(uint64_t));

	cmdlen = sizeof(tcs_req_get_policy_report);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetPolicyReport);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if(tpcmRspRetCode(rsp)){
		
		ret = tpcmRspRetCode(rsp);
		goto out;
	
	}
	

	if (tpcmRspLength (rsp) == sizeof (tcs_rsp_get_policy_report)){
		tpcm_memcpy(policy_report,&rsp->report,sizeof(struct policy_report));
	}
	else{
		httc_util_pr_error ("hter response length (%d < %ld)\n",
										tpcmRspLength (rsp), 
										(long int)sizeof(struct policy_report));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

EXPORT_SYMBOL(tcs_get_policy_report);





