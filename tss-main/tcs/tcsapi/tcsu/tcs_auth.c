#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "uutils.h"
#include "transmit.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_auth.h"


#pragma pack(push, 1)
typedef struct{
	COMMAND_HEADER;
	uint8_t  uaAuth[0];
}tcs_req_auth;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiPloyciesnumber;
	struct admin_auth_policy item[0];
}tcs_rsp_get_admin_auth_policies;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiCertnumber;
	struct admin_cert_item item[0];
}tcs_rsp_get_admin_list;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiResult;
}tcs_rsp_query_root_cert;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiResult;
}tcs_rsp_verify_ek_cert;

typedef struct{
	RESPONSE_HEADER;
	uint8_t key[KEY_LEN];
}tcs_rsp_key;

typedef struct{
	RESPONSE_HEADER;
	struct root_cert_item cert;
}tcs_rsp_ek_cert;

#pragma pack(pop)


int tcs_set_admin_cert(struct admin_cert_update *update,	int cert_type, int auth_length,
												unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if( update == NULL) return TSS_ERR_PARAMETER;

	if(ntohl(update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error ("cert size error exp:%ld act:%d!\n",(long int)sizeof(struct admin_cert_update),ntohl(update->be_size));
		return TSS_ERR_PARAMETER;
	}

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	memcpy(req->uaAuth + op,update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);

	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetAdminCert);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen)))	goto out;

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

int tcs_grant_admin_role(struct admin_cert_update *cert_update, int cert_type, int auth_length,
																				unsigned char *auth){
	int ret = 0;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if( cert_update == NULL) return TSS_ERR_PARAMETER;

	if( ntohl(cert_update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error ("cert size error exp:%ld act:%d!\n",(long int)sizeof(struct admin_cert_update),ntohl(cert_update->be_size));
		return TSS_ERR_PARAMETER;
	}

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	memcpy(req->uaAuth + op,cert_update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);

	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GrantAdminRole);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen)))	goto out;

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


int tcs_remove_admin_role(struct admin_cert_update *cert_update, int cert_type, int auth_length,
																					unsigned char *auth){

	int ret = 0;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if( cert_update == NULL) return TSS_ERR_PARAMETER;

	if( ntohl(cert_update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error ("cert size error exp:%ld act:%d!\n",(long int)sizeof(struct admin_cert_update),ntohl(cert_update->be_size));
		return TSS_ERR_PARAMETER;
	}

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	memcpy(req->uaAuth + op,cert_update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);

	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_RemoveAdminRole);

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

int tcs_get_admin_list(struct admin_cert_item **list, int *num){

	int ret = 0;
	int number = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32;
	uint8_t *cmd = NULL;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_admin_list *rsp = NULL;

	if(list == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_admin_list *)(cmd + CMD_DEFAULT_ALLOC_SIZE/32);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetAdminList);

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

	number = ntohl(rsp->uiCertnumber);
	if((((number * sizeof(struct admin_cert_item)) + sizeof (tcs_rsp_get_admin_list)) <= (CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32))
		&& (tpcmRspLength (rsp) == ((number * sizeof(struct admin_cert_item)) + sizeof (tcs_rsp_get_admin_list)))){
		if(number){
			if (NULL == (*list = httc_malloc(number * sizeof(struct admin_cert_item)))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
			}
			memcpy (*list, rsp->item, number * sizeof(struct admin_cert_item));
		}
		*num = number;

	}else{
		httc_util_pr_error ("Error response [rsplenth:%d  cert number:%d structlength:%ld] !\n",
			tpcmRspLength (rsp),number ,(long int)sizeof (tcs_rsp_get_admin_list));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_set_admin_auth_policies(struct admin_auth_policy_update *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t length = 0;
	uint32_t policylen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(update == NULL) return TSS_ERR_PARAMETER;

	policylen = (ntohl(update->be_number) * sizeof(struct admin_auth_policy) + sizeof(struct admin_auth_policy_update));
	length = sizeof(tcs_req_auth) + MAX_CMD_AUTH_SIZE + policylen + rspLen;
	if (NULL == (cmd = httc_malloc (length))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));

	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	op += httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	memcpy(req->uaAuth + op,update,policylen);

	cmdlen = sizeof(tcs_req_auth) + op + policylen;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetAdminAuthPolicies);

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

int tcs_get_admin_auth_policies(struct admin_auth_policy **list,	int *num){


	int ret = 0;
	int number = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_admin_auth_policies *rsp = NULL;

	if(list == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("[Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_admin_auth_policies *)(cmd + CMD_DEFAULT_ALLOC_SIZE/32);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetAdminAuthPolicies);

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

	number = ntohl(rsp->uiPloyciesnumber);
	if ((tpcmRspLength (rsp) == ((number * sizeof(struct admin_auth_policy)) + sizeof (tcs_rsp_get_admin_auth_policies)))&&
		(((number * sizeof(struct admin_auth_policy)) + sizeof (tcs_rsp_get_admin_auth_policies))
															<= (CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32))){
		if(number){
			if (NULL == (*list = (struct admin_auth_policy *)httc_malloc (number * sizeof(struct admin_auth_policy)))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TSS_ERR_NOMEM;
				*num = 0;
				goto out;
			}
			memcpy ((char *)*list, (char *)rsp->item, number * sizeof(struct admin_auth_policy));
		}
		*num = number;
	}
	else{
		httc_util_pr_error("Error response [rsplenth:%d policies number:%d structlength:%ld]\n",
						tpcmRspLength (rsp), number, (long int)sizeof(tcs_rsp_get_admin_auth_policies));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
out:
	if(cmd) httc_free(cmd);
	return ret;

}

int httc_get_admin_auth_policy(int id ,struct admin_auth_policy *policy){

	int i = 0;
	int ret = 0;
	int num = 0;
	struct admin_auth_policy *list = NULL;

	ret = tcs_get_admin_auth_policies(&list, &num);
	if(ret) return ret;
	if(num == 0) return TSS_ERR_ITEM_NOT_FOUND;

	for(; i < num ; i++){
		if(id == ntohl(list[i].be_object_id)){
			memcpy(policy,&(list[i]), sizeof(struct admin_auth_policy));
			httc_free(list);
			return TSS_SUCCESS;
		}
	}

	httc_free(list);
	return TSS_ERR_ITEM_NOT_FOUND;
}

static int tcs_common_request(struct root_cert_update *update,
					  const char *uid, int cert_type, int auth_length, unsigned char *auth, uint32_t cmd_code){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (TPCM_ORD_DeleteRoleCert != cmd_code)
	{
		if (update == NULL) return TSS_ERR_PARAMETER;
		if(ntohl(update->be_size) != sizeof(struct root_cert_update)){
			httc_util_pr_error ("cert size error exp:%ld size:%d!\n",(long int)sizeof(struct root_cert_update),ntohl(update->be_size));
			return TSS_ERR_PARAMETER;
		}
	}
	if (uid == NULL || auth == NULL )	return TSS_ERR_PARAMETER;
	if (auth_length <= 0 || auth_length > MAX_CERT_NEW_SIZE )	return TSS_ERR_PARAMETER;


	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	if (TPCM_ORD_DeleteRoleCert != cmd_code)
	{
		memcpy(req->uaAuth + op, update, sizeof(struct root_cert_update));
		op += sizeof(struct root_cert_update);
	}

	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(cmd_code);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen)))	goto out;

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

int tcs_set_root_cert(struct root_cert_update *update,
					  const char *uid, int cert_type, int auth_length, unsigned char *auth){
	return tcs_common_request(update, uid, cert_type, auth_length, auth, TPCM_ORD_SetRootCert);
}

int tcs_update_root_cert(struct root_cert_update *update,
					  const char *uid, int cert_type, int auth_length, unsigned char *auth){
	return tcs_common_request(update, uid, cert_type, auth_length, auth, TPCM_ORD_UpdateRootCert);
}

int tcs_query_root_cert(unsigned int *result){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tcs_rsp_query_root_cert *rsp = NULL;

	if(NULL == result) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tcs_rsp_query_root_cert *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdlen = sizeof(tcs_req_auth);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_QueryRootCert);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen)))	goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if(tpcmRspRetCode(rsp)){
		ret = tpcmRspRetCode(rsp);
		goto out;
	}
	*result = ntohl(rsp->uiResult);

out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_update_role_cert(struct root_cert_update *update,
					  const char *uid, int cert_type, int auth_length, unsigned char *auth){
	return tcs_common_request(update, uid, cert_type, auth_length, auth, TPCM_ORD_UpdateRoleCert);
}

int tcs_delete_role_cert(const char *uid, int cert_type, int auth_length, unsigned char *auth){
	return tcs_common_request(NULL, uid, cert_type, auth_length, auth, TPCM_ORD_DeleteRoleCert);
}

int tcs_generate_key (char * uid, uint32_t cert_type,uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key ){
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *cmd = NULL;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_key *rsp = NULL;

	if ((auth_length <= 0) || (auth_length > MAX_CERT_NEW_SIZE) || (index < 0) )	return TSS_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TSS_ERR_PARAMETER;
	//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_key *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)req + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen +=httc_insert_auth_align4(cert_type,auth_length,auth,(void*)req + cmdLen);
	/** Insert index */
	*(uint32_t *)((void*)cmd + cmdLen) = htonl (index);
	cmdLen += 4;
	/** Insert key id */
	if (id==NULL)
		memset ((void*)(req + cmdLen), 0, KEY_ID_LEN);
	else
		memcpy ((void*)(req + cmdLen), id, KEY_ID_LEN);
	cmdLen += KEY_ID_LEN;
	/** Insert cmd header */
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdLen);
	req->uiCmdCode = htonl(TPCM_ORD_GenerateKey);
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (tcs_rsp_key) != tpcmRspLength (rsp)){
			httc_util_pr_error ("Invalid response steam.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memset(key,0,KEY_LEN);
		memcpy(key,rsp->key,KEY_LEN);
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;

}


int tcs_get_index_pubkey (char * uid,uint32_t cert_type, uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key ){
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *cmd = NULL;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_key *rsp = NULL;

	if ((auth_length <= 0) || (auth_length > MAX_CERT_NEW_SIZE) || (index < 0) )	return TSS_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TSS_ERR_PARAMETER;
	//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_key *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)req + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen +=httc_insert_auth_align4(cert_type,auth_length,auth,(void*)req + cmdLen);
	/** Insert index */
	*(uint32_t *)((void*)cmd + cmdLen) = htonl (index);
	cmdLen += 4;
	/** Insert key id */
	if (id==NULL)
		memset ((void*)(req + cmdLen), 0, KEY_ID_LEN);
	else
		memcpy ((void*)(req + cmdLen), id, KEY_ID_LEN);
	cmdLen += KEY_ID_LEN;
	/** Insert cmd header */
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdLen);
	req->uiCmdCode = htonl(TPCM_ORD_GetPubKey);
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (tcs_rsp_key) != tpcmRspLength (rsp)){
			httc_util_pr_error ("Invalid response steam.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memset(key,0,KEY_LEN);
		memcpy(key,rsp->key,KEY_LEN);
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;

}
/* index  的 固定值2*/
int tcs_get_ek_pubkey (char * uid, uint32_t cert_type,uint32_t auth_length,unsigned char *auth,char * id,char *key ){
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *cmd = NULL;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_key *rsp = NULL;

	if ((auth_length <= 0) || (auth_length > MAX_CERT_NEW_SIZE))	return TSS_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TSS_ERR_PARAMETER;
	//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_key *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	cmdLen = sizeof (tpcm_req_header_st);
	cmdLen += httc_insert_uid_align4 (uid, (void*)req + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen +=httc_insert_auth_align4(cert_type,auth_length,auth,(void*)req + cmdLen);
	/** Insert index */
	*(uint32_t *)((void*)cmd + cmdLen) = htonl (EK_INDEX);
	cmdLen += 4;
	/** Insert key id */
	if (id==NULL)
		memset ((void*)(req + cmdLen), 0, KEY_ID_LEN);
	else
		memcpy ((void*)(req + cmdLen), id, KEY_ID_LEN);
	cmdLen += KEY_ID_LEN;
	/** Insert cmd header */
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdLen);
	req->uiCmdCode = htonl(TPCM_ORD_GetEKPubKey);
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (tcs_rsp_key) != tpcmRspLength (rsp)){
			httc_util_pr_error ("Invalid response steam.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memset(key,0,KEY_LEN);
		memcpy(key,rsp->key,KEY_LEN);
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;

}

int tcs_import_ek(struct root_cert_update *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth){
	return tcs_common_request(update, uid, cert_type, auth_length, auth, TPCM_ORD_ImportEK);
}

int tcs_verify_ek(struct root_cert_update *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth,int *result){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t policylen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tcs_rsp_verify_ek_cert *rsp = NULL;

	if(!result) return TSS_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || update == NULL )	return TSS_ERR_PARAMETER;
	if (auth_length <= 0 || auth_length > MAX_CERT_NEW_SIZE )	return TSS_ERR_PARAMETER;

	policylen = sizeof(struct root_cert_update);
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_auth *)cmd;
	rsp = (tcs_rsp_verify_ek_cert *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	op += httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	memcpy(req->uaAuth + op,update,policylen);

	cmdlen = sizeof(tcs_req_auth) + op + policylen;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_VerifyEK);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);
	if(TSS_SUCCESS == ret){
		*result = ntohl(rsp->uiResult);
	}

out:
	if(cmd) httc_free(cmd);
	return ret;
}

int tcs_get_ek(struct root_cert_item *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_auth *req = NULL;
	tcs_rsp_ek_cert *rsp = NULL;

	if (uid == NULL || auth == NULL || update == NULL )	return TSS_ERR_PARAMETER;
	if (auth_length <= 0 || auth_length > MAX_CERT_NEW_SIZE )	return TSS_ERR_PARAMETER;

	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_auth *)cmd;
	rsp = (tcs_rsp_ek_cert *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	op += httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);

	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetEK);

	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);
	if(TSS_SUCCESS == ret){
		memcpy((char *)update, &rsp->cert, ntohl(rsp->uiRspLength) - sizeof(tpcm_rsp_header_st));
	}

out:
	if(cmd) httc_free(cmd);
	return ret;
}



int tcs_update_root_cert_vir(struct root_cert_update_vir *update,const char *uid, int cert_type, int auth_length, unsigned char *auth,unsigned char *cert_auth){
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	uint32_t update_len = 0;
	int rspLen = 0;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (uid == NULL || auth == NULL ||cert_auth == NULL )	return TSS_ERR_PARAMETER;
	if (auth_length <= 0 || auth_length > MAX_CERT_NEW_SIZE )	return TSS_ERR_PARAMETER;
	if (update == NULL) return TSS_ERR_PARAMETER;
	update_len = sizeof(struct root_cert_update_vir)+(sizeof(struct root_cert_item)*(ntohl(update->be_num)))+CERT_AUTH_LEN;
	if(ntohl(update->be_size) != update_len){
		httc_util_pr_error ("cert size error exp:%ld size:%d!\n",(long int)update_len,ntohl(update->be_size));
		return TSS_ERR_PARAMETER;
	}
	rspLen = update_len+CMD_DEFAULT_ALLOC_SIZE/2;
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE+update_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + rspLen);
	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	memcpy(req->uaAuth + op, update, (update_len-CERT_AUTH_LEN));
	op += update_len-CERT_AUTH_LEN;
	memcpy(req->uaAuth + op, cert_auth, CERT_AUTH_LEN);
	op += CERT_AUTH_LEN;
	cmdlen = sizeof(tcs_req_auth) + op;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_UpdateRootCert_VIR);
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen)))	goto out;
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