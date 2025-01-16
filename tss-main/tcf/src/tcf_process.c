#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_process.h"
#include "tcsapi/tcs_process.h"
#include "tcsapi/tcs_process_def.h"
#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"
#include "tsbapi/tsb_admin.h"
#include "tutils.h"
#include "tcsapi/tcs_notice.h"


static int tcf_util_process_roles_serialize (struct process_role_user *user_roles, int num, int *length, struct process_role **roles){
	
	int i = 0;
	int j = 0;		
	uint32_t op = 0;
	uint32_t op_member = 0;
	uint32_t namelen = 0;
	uint32_t act_len = 0;
	struct process_role *cur = NULL;
	struct role_member *cur_member = NULL;

	for(;i < num;i++){
		act_len += sizeof(struct process_role);
		if(!user_roles[i].name){
			httc_util_pr_error ("user_roles not enough except:%d actual:%d\n", num, i - 1);
			return TCF_ERR_PARAMETER;
		}
		
		act_len += strlen((const char *)user_roles[i].name);
		if(strlen((const char *)user_roles[i].name)> MAX_PROCESS_NAME_LENGTH){
			httc_util_pr_error("role name too long (%ld).",(long int)strlen((const char *)user_roles[i].name));
			return TCF_ERR_PARAMETER;
		}
		
		act_len += sizeof(struct role_member) * user_roles[i].member_number;
		for(j = 0;j < user_roles[i].member_number;j++){
			if(!user_roles[i].members[j]){
				httc_util_pr_error ("user_roles member not enough except:%d actual:%d\n", user_roles[i].member_number, j - 1);
				return TCF_ERR_PARAMETER;
			}
			if(strlen((const char *)user_roles[i].members[j]) > MAX_PROCESS_NAME_LENGTH){
				httc_util_pr_error("member name too long (%ld).",(long int)strlen((const char *)user_roles[i].members[j]));
				return TCF_ERR_PARAMETER;
			}
			act_len += strlen((const char *)user_roles[i].members[j]);
		}
		act_len = HTTC_ALIGN_SIZE(act_len,4);	
	}

	if(NULL == (*roles = (struct process_role *)httc_malloc(act_len))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}

	for(i= 0;i < num;i++){
		cur = (struct process_role *)((uint8_t *)*roles + op);		
		namelen = strlen((const char *)user_roles[i].name);
		cur->be_name_length = htonl(namelen);
		cur->be_members_number = htonl(user_roles[i].member_number);
		memcpy(cur->members,user_roles[i].name,namelen);
		op_member = 0;
		for(j = 0;j < user_roles[i].member_number;j++){
			cur_member = (struct role_member *)(cur->members + namelen + op_member);
			cur_member->length = (uint8_t)strlen((const char *)user_roles[i].members[j]);
			memcpy(cur_member->name,user_roles[i].members[j],(uint32_t)cur_member->length);
			op_member += (uint32_t)cur_member->length;
			op_member += sizeof(struct role_member);
		}
		cur->be_members_length = htonl(op_member);
		op += HTTC_ALIGN_SIZE((sizeof(struct process_role) + op_member + namelen),4);
	}
	*length = act_len;
	return TCF_SUCCESS;

}




static int tcf_util_process_ids_serialize (struct process_identity_user *user_ids, int num, int *length, struct process_identity **ids){

	int i = 0;
	uint32_t op = 0;
	uint32_t act_len = 0;
	uint8_t name_len = 0;
	uint16_t hash_len = 0;
	struct process_identity *cur = NULL;

	for(i = 0;i < num;i++){
		if(!user_ids[i].hash || !user_ids[i].name){
			httc_util_pr_error ("hash or name error\n");
			return TCF_ERR_PARAMETER;
		}
		if(strlen((const char *)user_ids[i].name) > MAX_PROCESS_NAME_LENGTH){
			httc_util_pr_error("process name too long (%ld).",(long int)strlen((const char *)user_ids[i].name));
			return TCF_ERR_PARAMETER;
		}
		name_len = (uint8_t)strlen((const char *)user_ids[i].name);
		hash_len = (uint16_t)((user_ids[i].lib_number + 1) * user_ids[i].hash_length);
		act_len += HTTC_ALIGN_SIZE(sizeof(struct process_identity) + name_len + hash_len,4);		
	}
	
	if(NULL == (*ids = (struct process_identity *)httc_malloc(act_len))){
			httc_util_pr_error ("Req Alloc error!\n");
			return TCF_ERR_NOMEM;
	}
	
	for( i = 0;i < num;i++){

		cur = (struct process_identity *)((uint8_t *)*ids + op);		
		name_len = (uint8_t)strlen((const char *)user_ids[i].name);
		cur->name_length = name_len;
		if(user_ids[i].specific_libs > 255){
			httc_util_pr_error("process specific_libs too much (%d).",user_ids[i].specific_libs);
			if(*ids) httc_free(*ids);
			*ids = NULL;
			return TCF_ERR_PARAMETER;
		}
		cur->specific_libs = (uint8_t)user_ids[i].specific_libs;
		cur->be_lib_number = htons((uint16_t)user_ids[i].lib_number);
		hash_len = (uint16_t)((user_ids[i].lib_number + 1) * user_ids[i].hash_length);
		cur->be_hash_length = htons((uint16_t)user_ids[i].hash_length);		
		memcpy(cur->data,user_ids[i].hash,hash_len);
		memcpy(cur->data + hash_len,user_ids[i].name,name_len);
		op += HTTC_ALIGN_SIZE(sizeof(struct process_identity) + name_len + hash_len,4);
	}
	*length = act_len;
	return TCF_SUCCESS;

}

static int tcf_util_process_ids_extract (struct process_identity *ids, int num, int length,struct process_identity_user **user_ids)
{
	int i = 0;
	int op = 0;
	int hash_len = 0;
	struct process_identity_user *proc_ids_user = NULL;
	struct process_identity * cur = NULL;
	
	if (NULL == (proc_ids_user = httc_malloc (num * sizeof (struct process_identity_user)))){
		httc_util_pr_error ("Process ids memory alloc failed!\n");
		return TCF_ERR_NOMEM;
	}
	
	for (i = 0; i < num; i++){
		cur = (struct process_identity *)((uint8_t *)ids + op);
		proc_ids_user[i].hash_length = (uint32_t)ntohs(cur->be_hash_length);
		proc_ids_user[i].specific_libs = cur->specific_libs;
		proc_ids_user[i].lib_number = ntohs(cur->be_lib_number);
		hash_len = proc_ids_user[i].hash_length * (1 + proc_ids_user[i].lib_number);
		if (NULL == (proc_ids_user[i].name = httc_malloc ((int)cur->name_length + 1))){
			httc_util_pr_error ("Process ids[%d] name memory alloc failed!\n", i);
			tcf_free_process_ids (proc_ids_user, i + 1);
			return TCF_ERR_NOMEM;
		}
		memset(proc_ids_user[i].name,0,cur->name_length + 1);
		if(op + hash_len + (int)cur->name_length > length){
			httc_util_pr_error("Length error\n");
			tcf_free_process_ids (proc_ids_user, i + 1);
			return TCF_ERR_PARAMETER;
		}
		memcpy(proc_ids_user[i].name,cur->data + hash_len,(int)cur->name_length);
		
		if (NULL == (proc_ids_user[i].hash = httc_malloc (hash_len + 1))){
			httc_util_pr_error ("Process ids[%d] hash memory alloc failed!\n", i);
			tcf_free_process_ids (proc_ids_user, i + 1);
			return TCF_ERR_NOMEM;
		}
		memset(proc_ids_user[i].hash,0,hash_len + 1);		
		if(op + hash_len > length){
			httc_util_pr_error("Length error\n");
			tcf_free_process_ids (proc_ids_user, i + 1);
			return TCF_ERR_PARAMETER;
		}
		memcpy(proc_ids_user[i].hash,cur->data,hash_len);
		op += HTTC_ALIGN_SIZE((hash_len + cur->name_length + sizeof(struct process_identity)),4);
		if(op > length){
			httc_util_pr_error("Length error\n");
			tcf_free_process_ids (proc_ids_user, i + 1);
			return TCF_ERR_PARAMETER;
		}
	}
	*user_ids = proc_ids_user;
	return TCF_SUCCESS;
}

static int tcf_util_process_roles_extract (struct process_role *roles, int num,int length, struct process_role_user **user_roles)
{
	int i = 0, j = 0;
	int op = 0;
	int member_opt = 0;
	int role_name_length = 0;
	uint32_t member_length = 0;
	struct process_role *cur = NULL;
	struct role_member *member = NULL;
	struct process_role_user *proc_roles_user = NULL;

	if (NULL == (proc_roles_user = httc_malloc (2*num * sizeof (struct process_role_user)))){
		httc_util_pr_error ("Process roles memory alloc failed!\n");
		return TCF_ERR_NOMEM;
	}
	
	for (i = 0; i < num; i++){
		cur = (struct process_role *)((uint8_t *)roles + op);
		member_opt = role_name_length = ntohl (cur->be_name_length);
		member_length = ntohl(cur->be_members_length);		
		proc_roles_user[i].member_number = ntohl (cur->be_members_number);		
		if (NULL == (proc_roles_user[i].name = httc_malloc (role_name_length + 1))){
			httc_util_pr_error ("Process roles[%d] name memory alloc failed!\n", i);
			tcf_free_process_roles (proc_roles_user, i + 1);
			return TCF_ERR_NOMEM;
		}		
		memset(proc_roles_user[i].name,0,role_name_length + 1);
		if(op + member_opt > length){
			httc_util_pr_error("Length error op:%d  role_name_length:%d length:%d\n",op,role_name_length,length);
			tcf_free_process_roles (proc_roles_user, i + 1);
			return TCF_ERR_PARAMETER;
		}
		memcpy (proc_roles_user[i].name, cur->members, role_name_length);		
		if (NULL == (proc_roles_user[i].members = httc_malloc (proc_roles_user[i].member_number * sizeof (char *)))){
			httc_util_pr_error ("Process ids memory alloc failed!\n");
			return TCF_ERR_NOMEM;
		}		
		for (j = 0; j < proc_roles_user[i].member_number; j ++){			
			member = (struct role_member *)(cur->members + member_opt);
			if (NULL == (proc_roles_user[i].members[j] = httc_malloc (member->length + 1))){				
				httc_util_pr_error ("Process role_member[%d] memory alloc failed!\n", i);
				tcf_free_process_roles (proc_roles_user, i + 1);
				return TCF_ERR_NOMEM;
			}			
			memset(proc_roles_user[i].members[j],0,member->length + 1);
			if(op + member_opt + member->length > length){
				httc_util_pr_error("Length error op:%d  member length:%d length:%d\n",op + member_opt,member->length,length);
				tcf_free_process_roles (proc_roles_user, i + 1);
				return TCF_ERR_PARAMETER;
			}
			memcpy (proc_roles_user[i].members[j], member->name, member->length);
			member_opt += sizeof (struct role_member) + member->length;
			if(member_opt > member_length + role_name_length){
				httc_util_pr_error("Length error\n");
				tcf_free_process_roles (proc_roles_user, i + 1);
				return TCF_ERR_PARAMETER;
			}
		}
		
		member_opt += sizeof(struct process_role);
		op += HTTC_ALIGN_SIZE(member_opt,4);
		if(op > length){
			httc_util_pr_error("Length error member_length:%d length:%d\n",member_length,length);
			tcf_free_process_roles (proc_roles_user, i + 1);
			return TCF_ERR_PARAMETER;
		}
	}	
	*user_roles = proc_roles_user;
	return TCF_SUCCESS;
}


int tcf_prepare_update_process_identity(struct process_identity_user *process_ids,int id_number,
								unsigned char *tpcm_id,int tpcm_id_length, int action,uint64_t replay_counter,
								struct process_identity_update **update,int *olen){
								
	int ret = 0;
	int idlen = 0;
	struct process_identity *ids = NULL;
	
	if(tpcm_id == NULL || update == NULL || olen == NULL) return TCF_ERR_PARAMETER;
	if((process_ids == NULL)&&(id_number!=0) )
	{
			return TCF_ERR_PARAMETER;
	}
	
	if(tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id length error![%d > %d]\n",tpcm_id_length,MAX_TPCM_ID_SIZE);
		return TCF_ERR_PARAMETER;
	}
	
	if(id_number){
		ret = tcf_util_process_ids_serialize(process_ids,id_number,&idlen,&ids);
		if(ret) return ret;
	}
	
	if(NULL == (*update = (struct process_identity_update *)httc_malloc(sizeof(struct process_identity_update) + idlen))){
			httc_util_pr_error ("Req Alloc error!\n");
			if(ids) httc_free(ids);
			ids = NULL;
			return TCF_ERR_NOMEM;
	}
	
	(*update)->be_size = htonl(sizeof(struct process_identity_update));
	(*update)->be_action = htonl(action);
	(*update)->be_replay_counter = htonll(replay_counter);
	(*update)->be_item_number = htonl(id_number);
	(*update)->be_data_length = htonl(idlen);
	memcpy((*update)->tpcm_id,tpcm_id,tpcm_id_length);
	memcpy((*update)->data,(uint8_t *)ids,idlen);	
	*olen = idlen + sizeof(struct process_identity_update);
	
	if(ids) httc_free(ids);
	return ret;

}

int tcf_update_process_identity(
		struct process_identity_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth){
		
		int ret = 0;
		int length = 0;
		
		if(update == NULL) return TCF_ERR_PARAMETER;
		
		ret = tcs_update_process_identity(update,uid,auth_type,auth_length,auth);
		if(ret) return ret;
		
		length = ntohl(update->be_data_length);

		if ((ret = tsb_set_process_ids((const char *)update->data,length))){
			if(ret == -1){
				httc_util_pr_info ("tsb_set_process_ids : %d(0x%x)\n", ret, ret);
				}
			ret = TCF_SUCCESS;
		}
		httc_write_version_notices (ntohll (update->be_replay_counter), POLICY_TYPE_PROCESS_IDENTITY);
		return ret;
}



int tcf_get_process_ids(struct process_identity_user **ids,int *num){

	int ret = 0;
	int length = 0;
	struct process_identity *tcs_ids = NULL;
	
	if( ids == NULL || num == NULL) return TCF_ERR_PARAMETER;
	
	ret = tcs_get_process_ids(&tcs_ids,num,&length);
	if(ret) goto out;
	
	ret = tcf_util_process_ids_extract(tcs_ids,*num,length,ids);

out:
	if(tcs_ids) httc_free(tcs_ids);
	return ret;
}


int tcf_get_process_id(const unsigned char *name,struct process_identity_user **ids,int *num){

	int i = 0;
	int ret = 0;
	int match_num = 0;
	int length = 0;
	struct process_identity_user *matchids = NULL;
	
	if(name == NULL || ids == NULL || num == NULL) return TCF_ERR_PARAMETER;
	
	ret = tcf_get_process_ids(ids,num);
	if(ret) goto out;

	for(i = 0; i < *num; i++){
		if(!strcmp((const char *)name,(const char *)(*ids)[i].name)) match_num++;
	}

	if(NULL == (matchids = (struct process_identity_user *)httc_malloc(match_num * sizeof(struct process_identity_user)))){
			httc_util_pr_error ("Req Alloc error!\n");
			tcf_free_process_ids(*ids,*num);
			return TCF_ERR_NOMEM;
	}
	match_num = 0;
	
	for(i = 0; i < *num; i++){
		if(!strcmp((const char *)name,(const char *)(*ids)[i].name)){
			matchids[match_num].hash_length = (*ids)[i].hash_length;
			matchids[match_num].lib_number = (*ids)[i].lib_number;
			matchids[match_num].specific_libs = (*ids)[i].specific_libs;
			length = strlen((const char *)(*ids)[i].name);
			if(NULL == (matchids[match_num].name = httc_malloc(length + 1))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_process_ids(*ids,*num);
				tcf_free_process_ids(matchids,match_num);
				return TCF_ERR_NOMEM;
			}
			memset(matchids[match_num].name,0,length + 1);
			memcpy(matchids[match_num].name,(*ids)[i].name,length);

			length = (matchids[match_num].lib_number + 1) * matchids[match_num].hash_length;
			if(NULL == (matchids[match_num].hash = httc_malloc(length + 1))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_process_ids(*ids,*num);
				tcf_free_process_ids(matchids,match_num + 1);
				return TCF_ERR_NOMEM;
			}
			memset(matchids[match_num].hash,0,length + 1);
			memcpy(matchids[match_num].hash,(*ids)[i].hash,length);
			match_num++;
		}
	}
	
out:
	tcf_free_process_ids(*ids,*num);
	*ids = matchids;
	*num = match_num;
	return ret;

}

void tcf_free_process_ids(struct process_identity_user *ids,int num){
	if(ids){
		while (num--){ 
			if ((ids + num)->name) httc_free ((ids + num)->name);
			if ((ids + num)->hash) httc_free ((ids + num)->hash);
		}
		httc_free(ids);
	}
}


int tcf_prepare_update_process_roles(struct process_role_user *roles,int roles_number,unsigned char *tpcm_id,
				int tpcm_id_length, int action,uint64_t replay_counter, struct process_role_update **update,int *olen){

	int ret = 0;		
	int rllen = 0;
	struct process_role *rls = NULL;
	
	if(update == NULL ||  tpcm_id == NULL || olen == NULL) return TCF_ERR_PARAMETER;
	if((roles_number!=0)&&(roles == NULL))
	{
		return TCF_ERR_PARAMETER;
	}

	if(tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id length error![%d > %d]\n",tpcm_id_length,MAX_TPCM_ID_SIZE);
		return TCF_ERR_PARAMETER;
	}
	
	if(roles_number){
		ret = tcf_util_process_roles_serialize(roles,roles_number,&rllen,&rls);
		if(ret) return ret;
	}
	
	if(NULL == (*update = (struct process_role_update *)httc_malloc( rllen + sizeof(struct process_role_update)))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TCF_ERR_NOMEM;
	}		
	
	(*update)->be_size = htonl(sizeof(struct process_role_update));
	(*update)->be_action = htonl(action);
	(*update)->be_replay_counter = htonll(replay_counter);
	(*update)->be_item_number = htonl(roles_number);
	(*update)->be_data_length = htonl(rllen);
	memcpy((*update)->tpcm_id,tpcm_id,tpcm_id_length);
	memcpy((*update)->data,(uint8_t *)rls,rllen);	
	*olen = rllen + sizeof(struct process_role_update);
	
	if(rls) httc_free(rls);
	return ret;
}

int tcf_update_process_roles(struct process_role_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth){		
		
		int ret = 0;
		int length = 0;
		
		if(update == NULL) return TCF_ERR_PARAMETER;
		
		ret = tcs_update_process_roles(update,uid,auth_type,auth_length,auth);
		if(ret) return ret;
		
		length = ntohl(update->be_data_length);
		if ((ret = tsb_set_process_roles((const char *)update->data,length))){
			if(ret == -1){
				httc_util_pr_info ("tsb_set_process_roles : %d(0x%x)\n", ret, ret);
				}
			ret = TCF_SUCCESS;
		}
		httc_write_version_notices (ntohll (update->be_replay_counter), POLICY_TYPE_PROCESS_ROLE);
		
		return ret;
}


int tcf_get_process_roles(struct process_role_user **roles,int *num){


	int ret = 0;
	int length = 0;
	struct process_role *tcs_roles = NULL;

	if(num == NULL || roles == NULL) return TCF_ERR_PARAMETER;

	ret = tcs_get_process_roles(&tcs_roles,num,&length);
	if(ret) goto out;
	
	ret = tcf_util_process_roles_extract(tcs_roles,*num,length,roles);
	if(ret) goto out;
out:
	if(tcs_roles) httc_free(tcs_roles);
	return ret;	

}


int tcf_get_process_role(const unsigned char *name,struct process_role_user **roles){

	int i = 0, j = 0;
	int ret = 0;
	int num = 0;
	int length = 0;
	struct process_role_user *role = NULL;

	if(roles == NULL || name == NULL) return TCF_ERR_PARAMETER;
	
	ret = tcf_get_process_roles(&role,&num); 
	if(ret) goto out;
	
	for(; i < num; i++){
		if(!strcmp((const char *)name,(const char *)role[i].name)){
			if(NULL == (*roles = (struct process_role_user *)httc_malloc(sizeof(struct process_role_user)))){
				httc_util_pr_error ("Req Alloc error!\n");
				ret = TCF_ERR_NOMEM;
				goto out;
			}
			(*roles)->member_number = role[i].member_number;
			length = strlen((const char *)role[i].name);
			if(NULL == ((*roles)->name = httc_malloc(length + 1))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_process_roles(*roles,1);
				ret = TCF_ERR_NOMEM;
				goto out;
			}
			memset((*roles)->name, 0 ,length + 1);
			memcpy((*roles)->name,role[i].name,length); 
			if(NULL == ((*roles)->members = httc_malloc((*roles)->member_number * sizeof(char *)))){
				httc_util_pr_error ("Req Alloc error!\n");
				tcf_free_process_roles(*roles,1);
				ret = TCF_ERR_NOMEM;
				goto out;
			}
			for(; j < (*roles)->member_number; j++){
				length = strlen((const char *)role[i].members[j]);
				if(NULL == ((*roles)->members[j] = httc_malloc(length + 1))){
					httc_util_pr_error ("Req Alloc error!\n");
					tcf_free_process_roles(*roles,1);
					ret = TCF_ERR_NOMEM;
					goto out;
				}
				memset((*roles)->members[j], 0 ,length + 1);
				memcpy((*roles)->members[j],role[i].members[j],length);
			}	
			break;
		}
	}
out:
	tcf_free_process_roles(role,num);
	return ret;
}

void tcf_free_process_roles(struct process_role_user *roles,int num){
 if(roles){
		while (num--){
			if ((roles + num)->name) httc_free ((roles + num)->name);
			while ((roles + num)->member_number --)
				if ((roles + num)->members[(roles + num)->member_number]) httc_free ((roles + num)->members[(roles + num)->member_number]);
			if((roles + num)->members) httc_free((roles + num)->members);

		}
		httc_free(roles);
	}
}
