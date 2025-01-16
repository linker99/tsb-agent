#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tutils.h"
#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_auth.h"
#include "tcsapi/tcs_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_sm.h"


#define DEFULT_CERT_NUM 128


int tcf_set_admin_cert(struct admin_cert_update *update,
									int cert_type,
								    int auth_length,unsigned char *auth
						){

	return tcs_set_admin_cert(update, cert_type, auth_length, auth);
}


int tcf_grant_admin_role(struct admin_cert_update *cert_update,
						int auth_type,
						int auth_length,unsigned char *auth){

	return tcs_grant_admin_role(cert_update, auth_type, auth_length, auth);
}


int tcf_remove_admin_role(struct admin_cert_update *cert_update,
		int auth_type,
		int auth_length,unsigned char *auth){
	return tcs_remove_admin_role(cert_update, auth_type, auth_length, auth);
}



int tcf_set_admin_auth_policies(struct admin_auth_policy_update *update,
			const char *uid, int auth_type,
				int auth_length,unsigned char *auth){

	int ret = 0;
	ret = tcs_set_admin_auth_policies(update,uid,auth_type, auth_length, auth);
	if(ret) return ret;
	httc_write_version_notices (htonll (update->be_replay_counter), POLICY_TYPE_ADMIN_AUTH_POLICY);
	return ret;
}

int tcf_get_admin_auth_policies(struct admin_auth_policy **list,
		int *num){
	return tcs_get_admin_auth_policies(list, num);
}

int tcf_get_admin_list(struct admin_cert_info **list,	int *num){

	int i = 0;
	int ret = 0;
	int number = DEFULT_CERT_NUM;
	struct admin_cert_item *item = NULL;

	if(list == NULL || num == NULL) return TCF_ERR_PARAMETER;

	ret = tcs_get_admin_list(&item,&number);
	if(ret) return ret;

	if(NULL == (*list = (struct admin_cert_info *)httc_malloc(number * sizeof(struct admin_cert_info)))){
		httc_util_pr_error("Malloc error!\n");
		if(item) httc_free(item);
		return TCF_ERR_NOMEM;
	}
	memset(*list,0,number * sizeof(struct admin_cert_info));

	for(;i < number; i ++){
		if(!i){
			(*list + i)->is_root = 1;
		}else{
			(*list + i)->is_root = 0;
		}
		(*list + i)->cert_type = ntohl((item + i)->be_cert_type);
		(*list + i)->cert_len = ntohl((item + i)->be_cert_len);
		memcpy((*list + i)->name,(item + i)->name,TPCM_UID_MAX_LENGTH);
		if((*list + i)->cert_type != CERT_TYPE_PASSWORD_32_BYTE)
			memcpy((*list + i)->data,(item + i)->data,MAX_CERT_SIZE);
	}
	*num = number;
	if(item) httc_free(item);
	return ret;
}

int tcf_free_admin_list(struct admin_cert_info *list,	int list_size){

	if(list) httc_free(list);
	list = NULL;
	return TCF_SUCCESS;
}

int tcf_set_root_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						){

	return tcs_set_root_cert(update, uid, cert_type, auth_length, auth);
}

int tcf_update_root_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						){

	return tcs_update_root_cert(update, uid, cert_type, auth_length, auth);
}

int tcf_query_root_cert(unsigned int *result){
	return tcs_query_root_cert(result);
}

int tcf_update_role_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						){

	return tcs_update_role_cert(update, uid, cert_type, auth_length, auth);
}

int tcf_delete_role_cert(const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						){

	return tcs_delete_role_cert(uid, cert_type, auth_length, auth);
}



int tcf_generate_key (char * uid,uint32_t cert_type, uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key ){
    int ret = 0;
	if ((auth_length<=0) || (index<=0) )	return TCF_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TCF_ERR_PARAMETER;
//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
    ret = tcs_generate_key(uid,cert_type,auth_length,auth,index,id,key);
    return  ret;
}


int tcf_get_index_pubkey (char * uid,uint32_t cert_type, uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key ){
    int ret = 0;
	if ((auth_length<=0) || (index<=0) )	return TCF_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TCF_ERR_PARAMETER;
//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
    ret = tcs_get_index_pubkey(uid,cert_type,auth_length,auth,index,id,key);
    return  ret;
}


int tcf_get_ek_pubkey (char * uid, uint32_t cert_type,uint32_t auth_length,unsigned char *auth,char * id,char *key ){
    int ret = 0;
	if ((auth_length<=0)  )	return TCF_ERR_PARAMETER;
	if (uid == NULL || auth == NULL || key == NULL )	return TCF_ERR_PARAMETER;
//  if(id == NULL ) return TCF_ERR_PARAMETER;//预留
    ret = tcs_get_ek_pubkey(uid,cert_type,auth_length,auth,id,key);
    return  ret;
}


int tcf_import_ek(struct root_cert_update *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth){

	return tcs_import_ek(update, uid, cert_type, auth_length, auth);
}
int tcf_verify_ek(struct root_cert_update *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth, int *result){

	return tcs_verify_ek(update, uid, cert_type, auth_length, auth, result);
}

int tcf_get_ek(struct root_cert_item *update,
			const char *uid, int cert_type, int auth_length,unsigned char *auth){

	return tcs_get_ek(update, uid, cert_type, auth_length, auth);
}

int tcf_hash_sign(uint32_t index, uint8_t *digest, uint8_t *sig)
{
	return tcs_hash_sign(index, digest, sig);
}

int tcf_update_root_cert_vir(struct root_cert_update_vir *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth,unsigned char *cert_auth
						){
	return tcs_update_root_cert_vir(update, uid, cert_type, auth_length, auth,cert_auth);
}