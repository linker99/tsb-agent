#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>

#include "memdebug.h"
#include "kutils.h"
#include "debug.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_process.h"
#include "tcs_policy_mgmt.h"
#include "tcs_constant.h"

#pragma pack(push, 1)
typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_update_process_identity;

typedef struct{
	COMMAND_HEADER;
}tcs_req_get_process_ids;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiIdnumber;
	uint32_t uiIdlength;
	uint8_t ids[0];
}tcs_rsp_get_process_ids;

typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_update_process_roles;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiRolenumber;
	uint32_t uiRolelength;
	uint8_t roles[0];
}tcs_rsp_get_process_roles;
#pragma pack(pop)

int tcs_ioctl_update_process_ids (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int num = 0;
	int length = 0;
	struct process_identity *ids = NULL;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);
	if (0 == (tpcmRspRetCode(rsp)) && !ret){
		if (0 == (ret = tcs_get_process_ids (&ids, &num, &length))){
			ret = tcs_util_set_process_ids (ids, num, length);
		}
	}
	if(cmd) tdd_free_data_buffer(cmd);
	if (ids) httc_vfree (ids);
	return ret;
}

int tcs_ioctl_update_process_roles (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int num = 0;
	int length = 0;
	struct process_role *roles = NULL;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);
	if (0 == (tpcmRspRetCode(rsp)) && !ret){
		if (0 == (ret = tcs_get_process_roles (&roles, &num, &length))){
			ret = tcs_util_set_process_roles (roles, num, length);
		}
	}
	if(cmd) tdd_free_data_buffer(cmd);
	if (roles) httc_vfree (roles);
	return ret;
}

#ifndef PROCESS_SOFT

int tcs_update_process_identity(		struct process_identity_update *update, const char *uid,int cert_type,
													int auth_length,unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;	
	uint32_t ali_len = 0;
	uint32_t length = 0;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_update_process_identity *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(update == NULL) return TSS_ERR_PARAMETER;

	if(ntohl(update->be_size)!= sizeof(struct process_identity_update)){
		httc_util_pr_error ("Update size hter!\n");
		return TSS_ERR_PARAMETER;

	}

	length = sizeof(tcs_req_update_process_identity) + sizeof(struct process_identity_update) 
								+ ntohl(update->be_data_length) + MAX_CMD_AUTH_SIZE + rspLen;
	if(NULL == (cmd = tdd_alloc_data_buffer(length))){
		httc_util_pr_error("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_update_process_identity *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));

	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaData + op);
	op += ali_len;	
	tpcm_memcpy(req->uaData + op,update,sizeof(struct process_identity_update));
	op += sizeof(struct process_identity_update);
	tpcm_memcpy(req->uaData + op,update->data,ntohl(update->be_data_length));
	op += ntohl(update->be_data_length);	

	cmdlen = op + sizeof(tcs_req_update_process_identity);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_UpdateProcessIdentity);

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

int tcs_get_process_ids(struct process_identity **ids,int *num, int *length){

	int ret;
	int number;
	int idlen;
	uint8_t *cmd;
	uint32_t cmdlen;
	uint32_t rspLen;
	tpcm_req_header_st *req;
	tcs_rsp_get_process_ids *rsp = NULL;	
	if(ids == NULL || num == NULL || length == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_process_ids *)(cmd + CMD_DEFAULT_ALLOC_SIZE);
	rspLen = CMD_DEFAULT_ALLOC_SIZE;

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetProcessIds);

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
	
	if((tpcmRspLength (rsp) == (ntohl(rsp->uiIdlength) + sizeof(tcs_rsp_get_process_ids))) &&
	  (ntohl(rsp->uiIdlength) + sizeof(tcs_rsp_get_process_ids) <= CMD_DEFAULT_ALLOC_SIZE)){ 
		number = ntohl(rsp->uiIdnumber);
		idlen = ntohl(rsp->uiIdlength);
	}else{
		httc_util_pr_error("hter response [rsplength:%d Idlength:%d structlength:%ld]\n",
				tpcmRspLength (rsp) ,ntohl(rsp->uiIdlength) ,(long int)sizeof(tcs_rsp_get_process_ids));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	if(idlen){
		if(NULL == (*ids = httc_vmalloc(idlen))){
				httc_util_pr_error ("Req Alloc hter!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
		}
		tpcm_memcpy((char *)*ids, rsp->ids, idlen);
	}
	*num = number;
	*length = idlen;	
	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;	
}
int tcs_update_process_roles(struct process_role_update *update,	const char *uid,int cert_type,
																	int auth_length,unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;	
	uint32_t ali_len = 0;
	uint32_t length = 0;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_update_process_roles *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(update == NULL) return TSS_ERR_PARAMETER;

	if(ntohl(update->be_size) != sizeof(struct process_role_update)){
		httc_util_pr_error ("Update size hter!\n");
		return TSS_ERR_PARAMETER;
	}
	
	length = sizeof(tcs_req_update_process_roles) + sizeof(struct process_role_update) 
							+ ntohl(update->be_data_length) + MAX_CMD_AUTH_SIZE + rspLen;
	if(NULL == (cmd = tdd_alloc_data_buffer(length))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_update_process_roles *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));

	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaData + op);
	op += ali_len;	
	memcpy(req->uaData + op,update,sizeof(struct process_role_update));
	op += sizeof(struct process_role_update);
	memcpy(req->uaData + op,update->data,ntohl(update->be_data_length));
	op += ntohl(update->be_data_length);	

	cmdlen = op + sizeof(tcs_req_update_process_roles);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_UpdateProcessRoles);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);		
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

int tcs_get_process_roles(struct process_role **roles,int *num, int *length){

	int ret = 0;
	int number = 0;
	int rlslen = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_process_roles *rsp = NULL;

	if(roles == NULL || num == NULL || length == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (2*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_process_roles *)(cmd + CMD_DEFAULT_ALLOC_SIZE);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetProcessRoles);

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

	if((tpcmRspLength (rsp) == (ntohl(rsp->uiRolelength) + sizeof(tcs_rsp_get_process_roles)))&&
	  (ntohl(rsp->uiRolelength) + sizeof(tcs_rsp_get_process_roles) <= CMD_DEFAULT_ALLOC_SIZE)){ 
		number = ntohl(rsp->uiRolenumber);
		rlslen = ntohl(rsp->uiRolelength);
	}else{
		httc_util_pr_error("hter response [rsplenth:%d Rolelength:%d structlength:%ld]\n", 
						tpcmRspLength (rsp) ,ntohl(rsp->uiRolelength), (long int)sizeof(tcs_rsp_get_process_roles));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if(rlslen){
		if(NULL == (*roles = httc_vmalloc(rlslen))){
				httc_util_pr_error ("Req Alloc hter!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
		}
		tpcm_memcpy((char *)*roles,rsp->roles, rlslen);
	}
	*num = number;
	*length = rlslen;	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

#else
int tcs_get_process_ids(struct process_identity **ids,int *num, int *length)
{
	return tcs_util_read_policy (TCS_POLICY_PROCESS_IDS_PATH, (void*)ids, length, num);
}

int tcs_get_process_roles(struct process_role **roles,int *num, int *length)
{
	return tcs_util_read_policy (TCS_POLICY_PROCESS_ROLES_PATH, (void*)roles, length, num);
}
#endif

