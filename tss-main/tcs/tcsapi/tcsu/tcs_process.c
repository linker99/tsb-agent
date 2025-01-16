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
#include "tcs_process.h"
#include "file.h"
#include "tcs_constant.h"
#include "tcs_util_policy_update.h"

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
	uint8_t  ids[0];
}tcs_rsp_get_process_ids;

typedef struct{
	COMMAND_HEADER;
	uint8_t  uaData[0];
}tcs_req_update_process_roles;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiRolenumber;
	uint32_t uiRolelength;
	uint8_t  roles[0];
}tcs_rsp_get_process_roles;

#pragma pack(pop)

#ifdef PROCESS_SOFT

int tcs_update_process_identity(		struct process_identity_update *update, const char *uid,int cert_type,
													int auth_length,unsigned char *auth){
	int ret = 0;
	int action = 0;
	int number = 0;
	uint32_t policy_len = 0;
	uint32_t data_len = 0;
	const char *path = TCS_POLICY_PROCESS_IDS_PATH;
	uint64_t counter = 0;


	if(update == NULL) return TSS_ERR_PARAMETER;
	if(ntohl(update->be_size) != sizeof(struct process_identity_update)){
		httc_util_pr_error ("Update size error!\n");
		return TSS_ERR_PARAMETER;

	}
	
	counter = ntohll(update->be_replay_counter);
	number = ntohl(update->be_item_number);
	action = ntohl(update->be_action);
	policy_len = ntohl(update->be_data_length);
	data_len = policy_len + sizeof(struct process_identity_update);
	
	/*Update policy*/
	if( 0 != (ret =  tcs_util_update_policy(uid, cert_type, auth_length, auth, update, data_len, 
			path, update->data, policy_len,number, TCS_POLICY_TYPE_PROCESS_IDENTITY, action, counter))) return ret;

	return TSS_SUCCESS;
}

int tcs_get_process_ids(struct process_identity **ids,int *num,int *length){

	int ret = 0;
	const char *path = TCS_POLICY_PROCESS_IDS_PATH;

	if(ids == NULL || num == NULL || length == NULL) return TSS_ERR_PARAMETER;
	
	/*Get process ids*/
	if(0 != (ret = tcs_util_read_policy (path, (void **)ids, length,num))) return ret;

	return TSS_SUCCESS;
}


int tcs_update_process_roles(struct process_role_update *update,	const char *uid,int cert_type,
																	int auth_length,unsigned char *auth){
	int ret = 0;
	int action = 0;
	int number = 0;
	uint32_t policy_len = 0;
	uint32_t data_len = 0;
	const char *path = TCS_POLICY_PROCESS_ROLES_PATH;
	uint64_t counter = 0;


	if(update == NULL) return TSS_ERR_PARAMETER;
	if(ntohl(update->be_size) != sizeof(struct process_role_update)){
		httc_util_pr_error ("Update size error!\n");
		return TSS_ERR_PARAMETER;

	}
	
	counter = ntohll(update->be_replay_counter);
	number = ntohl(update->be_item_number);
	action = ntohl(update->be_action);
	policy_len = ntohl(update->be_data_length);
	data_len = policy_len + sizeof(struct process_role_update);
	
	/*Update policy*/
	if( 0 != (ret =  tcs_util_update_policy(uid, cert_type, auth_length, auth, update, data_len, 
			path, update->data, policy_len,number, TCS_POLICY_TYPE_PROCESS_ROLE, action, counter))) return ret;

	return TSS_SUCCESS;
	

}


int tcs_get_process_roles(struct process_role **roles,int *num,int *length){
	int ret = 0;
	const char *path = TCS_POLICY_PROCESS_ROLES_PATH;

	if(roles == NULL || num == NULL || length == NULL) return TSS_ERR_PARAMETER;
	
	/*Get process ids*/
	if(0 != (ret = tcs_util_read_policy (path, (void **)roles, length,num))) return ret;

	return TSS_SUCCESS;	
}

#else
int tcs_update_process_identity(		struct process_identity_update *update, const char *uid,int cert_type,
													int auth_length,unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;	
	uint32_t ali_len = 0;
	uint32_t length = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_update_process_identity *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(ntohl(update->be_size) != sizeof(struct process_identity_update)){
		httc_util_pr_error ("Update size error!\n");
		return TSS_ERR_PARAMETER;

	}

	length = sizeof(tcs_req_update_process_identity) + sizeof(struct process_identity_update) 
							+ ntohl(update->be_data_length) + MAX_CMD_AUTH_SIZE + rspLen;
	if(NULL == (cmd = httc_malloc(length))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_update_process_identity *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));

	ali_len = httc_insert_uid_align4(uid,req->uaData + op);
	op += ali_len;
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaData + op);
	op += ali_len;	
	memcpy(req->uaData + op,update,sizeof(struct process_identity_update));
	op += sizeof(struct process_identity_update);	
	memcpy(req->uaData + op,update->data,ntohl(update->be_data_length));
	op += ntohl(update->be_data_length);
	
	cmdlen = op + sizeof(tcs_req_update_process_identity);	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_UpdateProcessIdentity);

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

int tcs_get_process_ids(struct process_identity **ids,int *num,int *length){

	int ret = 0;
	int number = 0;
	int idlen = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_process_ids *rsp = NULL;
	int rspLen = 0;
	if(ids == NULL || num == NULL || length == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_process_ids *)(cmd + sizeof(tpcm_req_header_st));
	rspLen = 4*CMD_DEFAULT_ALLOC_SIZE - sizeof(tpcm_req_header_st);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetProcessIds);
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

		
	if((tpcmRspLength (rsp) == (ntohl(rsp->uiIdlength) + sizeof(tcs_rsp_get_process_ids))) &&
	  (ntohl(rsp->uiIdlength) + sizeof(tcs_rsp_get_process_ids) <= (4*CMD_DEFAULT_ALLOC_SIZE - sizeof(tpcm_req_header_st)))){ 
		number = ntohl(rsp->uiIdnumber);
		idlen = ntohl(rsp->uiIdlength);
	}else{
		httc_util_pr_error("Error response [rsplength:%d Idlength:%d structlength:%ld]\n",
				tpcmRspLength (rsp) ,ntohl(rsp->uiIdlength) , (long int)sizeof(tcs_rsp_get_process_ids));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	if(idlen){
		if(NULL == (*ids = httc_malloc(idlen))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
		}
		memcpy((char *)*ids, rsp->ids, idlen);
	}
	*num = number;
	*length = idlen;

out:
	if(cmd) httc_free(cmd);
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
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_update_process_roles *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(ntohl(update->be_size) != sizeof(struct process_role_update)){
		httc_util_pr_error ("Update size error!\n");
		return TSS_ERR_PARAMETER;
	}
	
	length = sizeof(tcs_req_update_process_roles) + sizeof(struct process_role_update) 
						+ ntohl(update->be_data_length) + MAX_CMD_AUTH_SIZE + rspLen;
	if(NULL == (cmd = httc_malloc(length))){
		httc_util_pr_error ("Req Alloc error!\n");
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

int tcs_get_process_roles(struct process_role **roles,int *num,int *length){

	int ret = 0;
	int number = 0;
	int rlslen = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	int rspLen = 0;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_process_roles *rsp = NULL;
	if (NULL == (cmd = httc_malloc (4*CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_process_roles *)(cmd + sizeof(tpcm_req_header_st));
	rspLen = 4*CMD_DEFAULT_ALLOC_SIZE - sizeof(tpcm_req_header_st);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetProcessRoles);
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
				
	if((tpcmRspLength (rsp) == (ntohl(rsp->uiRolelength) + sizeof(tcs_rsp_get_process_roles)))&&
	  (ntohl(rsp->uiRolelength) + sizeof(tcs_rsp_get_process_roles) <= (4*CMD_DEFAULT_ALLOC_SIZE - sizeof(tpcm_req_header_st)))){ 
		number = ntohl(rsp->uiRolenumber);
		rlslen = ntohl(rsp->uiRolelength);
	}else{
		httc_util_pr_error("Error response [rsplenth:%d Rolelength:%d structlength:%ld]\n", 
						tpcmRspLength (rsp) ,ntohl(rsp->uiRolelength), (long int)sizeof(tcs_rsp_get_process_roles));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if(rlslen){
		if(NULL == (*roles = httc_malloc(rlslen))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
		}
		memcpy((char *)*roles,rsp->roles, rlslen);
	}
	*num = number;
	*length = rlslen;
	
out:
	if(cmd) httc_free(cmd);
	return ret;
}
#endif

