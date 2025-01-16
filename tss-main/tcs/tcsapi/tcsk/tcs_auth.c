#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_auth.h"
#include "tcs_policy_mgmt.h"

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

#pragma pack(pop)

int tcs_ioctl_set_admin_auth_policies (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int num = 0;	
	uint8_t *cmd = NULL;
	struct admin_auth_policy *policy = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);
	if (0 == (tpcmRspRetCode(rsp)) && !ret){
		if (0 == (ret = tcs_get_admin_auth_policies (&policy, &num))){
			ret = tcs_util_set_admin_auth_policies (policy, num);
		}
	}
	
	if (policy) httc_vfree (policy);
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

int tcs_set_admin_cert(struct admin_cert_update *update,	int cert_type, int auth_length,
												unsigned char *auth){
	int ret = 0;	
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(update == NULL) return TSS_ERR_PARAMETER;
		
	if(ntohl(update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error("cert size hter!\n");
		return TSS_ERR_PARAMETER;
	}
	
	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	tpcm_memcpy(req->uaAuth + op,update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);
	
	cmdlen = sizeof(tcs_req_auth) + op;	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetAdminCert);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen)))	goto out;
	
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

EXPORT_SYMBOL(tcs_set_admin_cert);

int tcs_grant_admin_role(struct admin_cert_update *cert_update, int cert_type, int auth_length,
																				unsigned char *auth){
	int ret = 0;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(cert_update == NULL ) return TSS_ERR_PARAMETER;

	if(ntohl(cert_update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error ("cert size hter!\n");
		return TSS_ERR_PARAMETER;
	}
	
	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;	
	tpcm_memcpy(req->uaAuth + op,cert_update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);
	
	cmdlen = sizeof(tcs_req_auth) + op;
	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GrantAdminRole);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen)))	goto out;
	
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

EXPORT_SYMBOL(tcs_grant_admin_role);


int tcs_remove_admin_role(struct admin_cert_update *cert_update, int cert_type, int auth_length,
																					unsigned char *auth){

	int ret = 0;
	uint32_t op = 0;
	uint32_t ali_len = 0;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(cert_update == NULL ) return TSS_ERR_PARAMETER;

	if(ntohl(cert_update->be_size) != sizeof(struct admin_cert_update)){
		httc_util_pr_error ("cert size hter!\n");
		return TSS_ERR_PARAMETER;
	}
	
	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
	
	ali_len = httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	op += ali_len;
	tpcm_memcpy(req->uaAuth + op,cert_update,sizeof(struct admin_cert_update));
	op += sizeof(struct admin_cert_update);
	
	cmdlen = sizeof(tcs_req_auth) + op;
	
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_RemoveAdminRole);
	
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

EXPORT_SYMBOL(tcs_remove_admin_role);

																					

int tcs_get_admin_list(struct admin_cert_item **list, int *num){

	int ret = 0;
	int number = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_admin_list *rsp = NULL;

	if(list == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_admin_list *)(cmd + CMD_DEFAULT_ALLOC_SIZE/32);

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetAdminList);
	
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
	
	number = ntohl(rsp->uiCertnumber);		
	if((((number * sizeof(struct admin_cert_item)) + sizeof (tcs_rsp_get_admin_list)) <= (CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32))
		&& (tpcmRspLength (rsp) == ((number * sizeof(struct admin_cert_item)) + sizeof (tcs_rsp_get_admin_list)))){
		if(number){
			if (NULL == (*list = httc_vmalloc(number * sizeof(struct admin_cert_item)))){
				httc_util_pr_error ("Req Alloc hter!\n");
				ret = TSS_ERR_NOMEM;
				goto out;
			}
			tpcm_memcpy (*list, rsp->item, number * sizeof(struct admin_cert_item));
		}		
		*num = number;
		
	}else{
		httc_util_pr_error ("hter response [rsplenth:%d  cert number:%d structlength:%ld] !\n",
			tpcmRspLength (rsp),number ,(long int)sizeof (tcs_rsp_get_admin_list));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;


}

EXPORT_SYMBOL(tcs_get_admin_list);

int tcs_set_admin_auth_policies(struct admin_auth_policy_update *update, const char *uid, int cert_type,
				int auth_length,unsigned char *auth){

	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t length = 0;
	uint32_t policylen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	tcs_req_auth *req = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(update == NULL) return TSS_ERR_PARAMETER;

	policylen = (ntohl(update->be_number) * sizeof(struct admin_auth_policy) + sizeof(struct admin_auth_policy_update));
	length = sizeof(tcs_req_auth) + MAX_CMD_AUTH_SIZE + policylen + rspLen;	
	if (NULL == (cmd = tdd_alloc_data_buffer (length))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	req = (tcs_req_auth *)cmd;
	rsp = (tpcm_rsp_header_st *)(cmd + (length - rspLen));
	
	op = httc_insert_uid_align4(uid,req->uaAuth + op);
	op += httc_insert_auth_align4(cert_type,auth_length,auth,req->uaAuth + op);
	tpcm_memcpy(req->uaAuth + op,update,policylen);
	
	cmdlen = sizeof(tcs_req_auth) + op + policylen;
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_SetAdminAuthPolicies);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)&rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

EXPORT_SYMBOL(tcs_set_admin_auth_policies);

int tcs_get_admin_auth_policies(struct admin_auth_policy **list,	int *num){


	int ret = 0;
	int number = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32;
	tpcm_req_header_st *req = NULL;
	tcs_rsp_get_admin_auth_policies *rsp = NULL;

	if(list == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st *)cmd;
	rsp = (tcs_rsp_get_admin_auth_policies *)cmd + CMD_DEFAULT_ALLOC_SIZE/32;

	cmdlen = sizeof(tpcm_req_header_st);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdlen);
	req->uiCmdCode = htonl(TPCM_ORD_GetAdminAuthPolicies);
	
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

	number = ntohl(rsp->uiPloyciesnumber);
	if ((tpcmRspLength (rsp) == ((number * sizeof(struct admin_auth_policy)) + sizeof (tcs_rsp_get_admin_auth_policies)))&&
		(((number * sizeof(struct admin_auth_policy)) + sizeof (tcs_rsp_get_admin_auth_policies)) 
															<= (CMD_DEFAULT_ALLOC_SIZE - CMD_DEFAULT_ALLOC_SIZE/32))){		
		if(number){		
			if (NULL == (*list = (struct admin_auth_policy *)httc_vmalloc (number * sizeof(struct admin_auth_policy)))){
				httc_util_pr_error ("Req Alloc hter!\n");
				ret = TSS_ERR_NOMEM;
				*num = 0;
				goto out;
			}		
			tpcm_memcpy ((char *)*list, (char *)rsp->item, number * sizeof(struct admin_auth_policy));
		}
		*num = number;
	}
	else{
		httc_util_pr_error("hter response [rsplenth:%d policies number:%d structlength:%ld]\n", 
						tpcmRspLength (rsp), number, (long int)sizeof(tcs_rsp_get_admin_auth_policies));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}	
out:
	if(cmd) tdd_free_data_buffer(cmd);
	return ret;

}

EXPORT_SYMBOL(tcs_get_admin_auth_policies);


int	tcs_ioctl_update_cert_root (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen){

	int ret = 0;
	int i=0;
	int j=0;
	uint8_t *cmd = NULL;
	uint32_t op = 0;
	uint32_t cmdlen = 0;
	uint32_t update_len = 0;
	uint32_t uid_len = 0;
	uint32_t auth_len = 0;	
	uint32_t update_num = 0;
	struct root_cert_item *temp = NULL;
	uint64_t * cert_data = NULL;
	uid_len =httc_align_size(htonl(*(uint32_t*)(ucmd+UID_LEN_OFFSET)),4) ;
	auth_len = httc_align_size(htonl(*(uint32_t*)(ucmd+AUTH_LEN_OFFSET+uid_len)),4) ;
	update_num = htonl(*(uint32_t*)((ucmd+UPDATE_NUM_OFFSET+uid_len+auth_len)));
	//printk("uid_len  auth_len  update_num %d %d %d\n",uid_len,auth_len,update_num);
	update_len = sizeof(struct root_cert_update_vir)+(sizeof(struct root_cert_item_vir)*(update_num))+CERT_AUTH_LEN;
	//printk("update_len %d\n",update_len);
	if ((int)update_len > (int)LIMIT_CMD_SIZE){
		httc_util_pr_error ("munit is too large!\n");
		ret = TSS_ERR_INPUT_EXCEED;
		goto out;
	}
	if (NULL == (cmd = tdd_alloc_data_buffer (MAX_CMD_LEN+update_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if(NULL == (cert_data = vmalloc(update_num *sizeof(uint64_t)))) {
		httc_util_pr_error ("Alloc error!\n");
		if(cmd) tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	} 
	memcpy(cmd,ucmd,BASE_DATA_LEN+uid_len+auth_len);
	op += BASE_DATA_LEN+uid_len+auth_len;
	for(i=0;i<update_num;i++){
		temp = (struct root_cert_item *)(ucmd+BASE_DATA_LEN+uid_len+auth_len+i*(8+MAX_CERT_NEW_SIZE));
		memcpy(cmd+op,temp,8);
		op += 8;
		//printk("temp->be_cert_len %d",htonl(temp->be_cert_len));
		if (0 == (cert_data[i] = (uint64_t)httc_kmalloc(htonl(temp->be_cert_len),GFP_KERNEL))) {
			for(j=0;j<i;j++){
				if(cert_data[i]) httc_kfree((char *)cert_data[i]);
			}
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		//printk("cert_data[i] %lx ",(unsigned long)cert_data[i]);
		*(uint64_t *)(cmd+op) = htonll(cert_data[i]);
		memcpy((char *)(cert_data[i]),temp->data,htonl(temp->be_cert_len));
		tpcm_util_cache_flush ((char *)(cert_data[i]), htonl(temp->be_cert_len));
		op += 8;
	}
	memcpy(cmd+op,ucmd+BASE_DATA_LEN+uid_len+auth_len+update_num*(8+MAX_CERT_NEW_SIZE),CERT_AUTH_LEN);
	op += CERT_AUTH_LEN;
	cmdlen = op;
	*(uint32_t *)(cmd+DATA_LEN_OFFSET)=htonl(cmdlen);
	*(uint32_t *)(cmd+CERT_LEN_OFFSET+uid_len+auth_len)=htonl(cmdlen-CERT_LEN_OFFSET-uid_len-auth_len);
	ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, rspLen);
out:
	for(i=0;i<update_num;i++){
		if(cert_data[i]) httc_kfree ((char *)cert_data[i]);
		cert_data[i]=0;
	}
	if(cert_data)  vfree(cert_data);
	if(cmd) tdd_free_data_buffer (cmd);
	return ret;
}
