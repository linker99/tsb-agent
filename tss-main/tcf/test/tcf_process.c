#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/mem.h>

#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_process.h"
#include "tcsapi/tcs_process.h"
#include "tcsapi/tcs_process_def.h"
#include "tcsapi/tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"
#include "../src/tutils.h"


#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128
#define MAX_NUMBER		20


uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
uint8_t  *name[MAX_NUMBER] = {NULL};
uint32_t test_num = 1;
uint32_t sec_test_num = 10;
static void usage ()
{
	printf ("\n"
			" Usage: ./tcf_process -c <cert_type> -k <key> -u <uid> [-N] <number> -n <name> -o <operation> [-t] <type>\n"
			"        -c <cert_type>      - The cert_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -k <key>            - The privkey string + pubkey string\n"
			"        -u <uid>            - The uid\n"
			"        -n <name>           - The name of process or role\n"
			"        -N <number>         - The number of process or role(default 1)\n"
			"        -o <operation>      - (default)0:tcf_prepare_update_process_identity\n"
			"                                       1:tcf_update_process_identity\n"
			"                                       2:tcf_get_process_ids\n"
			"                                       3:tcf_get_process_id\n"
			"                                       4:tcf_prepare_update_process_roles\n"
			"                                       5:tcf_update_process_roles\n"
			"                                       6:tcf_get_process_roles\n"
			"                                       7:tcf_get_process_role\n"
			"        -t <operation_type> - (default)0:set 1:add 2:delete 3:replace\n"
			"    eg. ./tcf_process -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -n identity -o 0 -t 0\n"
			"        ./tcf_process -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -N 2 -n one two -o 0 -t 0\n\n");
}

int build_process_identity_user(struct process_identity_user *id,int num){

	int i = 0;
	for(; i < num; i++){
		if(NULL == (id[i].name = httc_malloc(strlen((const char*)name[i]) + 1))){
			printf("[Error] Malloc error!\n");
			return -1;
		}
		memcpy(id[i].name,name[i],strlen((const char*)name[i]) + 1);
		id[i].hash_length = DEFAULT_HASH_SIZE;
		id[i].specific_libs = 1;
		id[i].lib_number = 1;
		if(NULL == (id[i].hash = httc_malloc((id[i].lib_number + 1) * id[i].hash_length))){
			printf("[Error] Malloc error!\n");
			return -1;
		}
		sm3(name[i],strlen((const char *)name[i]) + 1, id[i].hash);
		memset(id[i].hash + id[i].hash_length ,i + 1,id[i].hash_length);
//		memset(id[i].hash ,'1',id[i].hash_length);
//		memset(id[i].hash + id[i].hash_length ,'2',id[i].hash_length);
//		httc_util_dump_hex ("ids", id[i].hash ,2*DEFAULT_HASH_SIZE);
	}	
	return 0;
}

int build_role_user(struct process_role_user *role, int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		role[i].member_number = sec_test_num;
		if(NULL == (role[i].name = httc_malloc(strlen((const char*)name[i]) + 1))){
			printf("[Error] Malloc error!\n");
			return -1;
		}
		memcpy(role[i].name,name[i],strlen((const char*)name[i]) + 1);
		
		if(NULL == (role[i].members = httc_malloc(role[i].member_number * sizeof(char*)))){
			printf("[Error] Malloc error!\n");
			return -1;
		}
		
		for(j = 0;j < sec_test_num; j++){
			if(NULL == (role[i].members[j] = httc_malloc(7))){
				printf("[Error] Malloc error!\n");
				return -1;
			}
			memset(role[i].members[j],0,7);
			memcpy(role[i].members[j],"member",6);
		}
	}
	return 0;
}


void show_process(struct process_identity_user *ids,int num){

	int i = 0;	
	for(;i < num; i++){
		printf("================RUN:%d================\n",i);
		printf ("ids[%d] name: %s\n",i, ids[i].name);
		printf ("ids[%d] hash_length: %d\n",i, ids[i].hash_length);
		printf ("ids[%d] specific_libs: %s\n",i, ids[i].name == 0 ? "USE" : "UNUSE");
		printf ("ids[%d] lib number: %d\n",i, ids[i].lib_number);
		httc_util_dump_hex ("HASH IS", ids[i].hash ,strlen((const char*)ids[i].hash));		
	}
	if(ids) tcf_free_process_ids(ids,num);
}

void show_role(struct process_role_user *roles,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("================RUN:%d================\n",i);
		printf ("roles[%d] name: %s\n",i, roles[i].name);
		printf ("roles[%d] member_number: %u\n",i, roles[i].member_number);
		for(j = 0 ;j < roles[i].member_number; j++){
			printf ("[%d] member.name: %s\n",j, roles[i].members[j]);
		}
	}
	if(roles) tcf_free_process_roles(roles,num);
}


int httc_sign_verify(const unsigned char *dgst, int dlen,
                unsigned char *privkey, unsigned int privkey_len,
                unsigned char *pubkey, unsigned int pubkey_len,
                unsigned char **sig, unsigned int *siglen){

	int ret = 0;
	ret = os_sm2_sign ((const uint8_t *)dgst, dlen, privkey, privkey_len, pubkey, pubkey_len, sig, siglen);
	if (ret){
		printf ("Sign for reference failed!\n");
		return -1;
	}

	ret = os_sm2_verify ((const uint8_t *)dgst, dlen, pubkey, pubkey_len, *sig, *siglen);
	if (ret){
		printf ("Verify for reference failed!\n");
	}
	return ret;
}


int main(int argc,char **argv){

	int i = 0;
	int ch = 0;
	int opt = 0;
	int ret = 0;
	int num = 0;
	int cur = 0;
	int cert_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int opt_type = POLICY_ACTION_SET;	
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	const char *uid = NULL;
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	uint64_t replay_counter;
	
	struct process_identity_user *process_ids = NULL;
	struct process_identity_update *idupdate = NULL;
	int idlength = 0;
	struct process_identity_user *ids = NULL;

	struct process_role_user *roles = NULL;
	struct process_role_update *rlupdate = NULL;
	int rllength = 0;
	struct process_role_user *rls = NULL;
	

	if(argc < 3){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "c:k:u:n:N:o:t:h")) != -1)
	{
		switch (ch) 
		{
			case 'c':
				cert_type = atoi(optarg);
				break;
			case 'k':
				KeytStr = optarg;
				keystrlen = strlen((const char *)KeytStr);
				if(keystrlen != TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN){
					usage();
					return -1;
				}
				httc_util_str2array(privkey,KeytStr,TPCM_PRIVKEY_STR_LEN);
				httc_util_str2array(pubkey,KeytStr + TPCM_PRIVKEY_STR_LEN,TPCM_PUBKEY_STR_LEN);
//				httc_util_dump_hex ("privkey", privkey , TPCM_PRIVKEY_STR_LEN/2);
//				httc_util_dump_hex ("pubkey", pubkey , TPCM_PUBKEY_STR_LEN/2);
				break;
			case 'u':
				uid = optarg;
				break;
			case 'n':
				name[0] = optarg;
				if(test_num > MAX_NUMBER){
					printf("Max test numebr is %d\n",MAX_NUMBER);
					return -1;
				}
//				printf("optind:%d\n",optind);
				if(test_num > 1){
					cur = optind - 1;
					for(;i < test_num;i++){						
						name[i] = argv[cur];
						cur += 1;
					}
				}
				break;
			case 'N':
				test_num = atoi(optarg);
				break;
			case 'o':
				opt = atoi(optarg);
				break;
			case 't':
				opt_type = atoi(optarg);
				break;
			case 'h':
				usage ();
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}	
	
	if(opt == 0){
		
		process_ids = httc_malloc(test_num * sizeof (struct process_identity_user));
		ret = build_process_identity_user(process_ids, test_num);
		if(ret) goto out;
		
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}	
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		ret = tcf_prepare_update_process_identity(process_ids,test_num,tpcm_id,tpcm_id_length,opt_type,replay_counter,
		&idupdate,&idlength);		
		if(ret){
			printf("[Error] tcf_prepare_update_process_identity ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		httc_util_dump_hex("update",(uint8_t *)idupdate,idlength);
		goto out;
	}else if(opt == 1){
		process_ids = httc_malloc(test_num * sizeof (struct process_identity_user));
		ret = build_process_identity_user(process_ids, test_num);
		if(ret) goto out;
		
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}	
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		ret = tcf_prepare_update_process_identity(process_ids,test_num,tpcm_id,tpcm_id_length,opt_type,replay_counter,
		&idupdate,&idlength);
		if(ret){
			printf("[Error] tcf_prepare_update_process_identity ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		ret = httc_sign_verify((const unsigned char *)idupdate,idlength,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
		ret = tcf_update_process_identity(idupdate,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_update_process_identity ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 2){
		ret = tcf_get_process_ids(&ids,&num);
		if(ret){
			printf("[Error] tcf_get_process_ids ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		if(ids) show_process(ids,num);
		goto out;
	}else if(opt == 3){
		for(i=0;i<test_num;i++){
			ret = tcf_get_process_id((const unsigned char *)name[i],&ids,&num);
			if(ret){
				printf("[Error] tcf_get_process_ids ret:0x%08X\n",ret);
				ret = -1;
				goto out;
			}
			if(ids) show_process(ids,num);
		}
		goto out;
	}else if(opt == 4){
	
		roles = httc_malloc(test_num * sizeof (struct process_role_user));
		ret = build_role_user(roles, test_num);
		if(ret) goto out;
	
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}
		
		ret = tcf_prepare_update_process_roles(roles,test_num,tpcm_id,tpcm_id_length,opt_type,replay_counter,
		&rlupdate,&rllength);		
		if(ret){
			printf("[Error] tcf_prepare_update_process_roles ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		httc_util_dump_hex("update",(uint8_t *)rlupdate,rllength);
		goto out;
	}else if(opt == 5){
		
		roles = httc_malloc(test_num * sizeof (struct process_role_user));
		ret = build_role_user(roles, test_num);
		if(ret) goto out;
			
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}

		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}
		ret = tcf_prepare_update_process_roles(roles,test_num,tpcm_id,tpcm_id_length,opt_type,replay_counter,
		&rlupdate,&rllength);
//		httc_util_dump_hex ((const char *)"rl", rlupdate , rllength);
		if(ret){
			printf("[Error] tcf_prepare_update_process_roles ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		ret = httc_sign_verify((const unsigned char *)rlupdate,rllength,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
//		httc_util_dump_hex ((const char *)"rl22222", rlupdate , rllength);
		ret = tcf_update_process_roles(rlupdate,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcf_update_process_roles ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 6){
		ret = tcf_get_process_roles(&rls,&num);
		if(ret){
			printf("[Error] tcf_get_process_roles ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		if(rls) show_role(rls,num);
		goto out;
	}else if(opt == 7){
		for(i=0;i<test_num;i++){
			ret = tcf_get_process_role((const unsigned char *)name[i],&rls);
			if(ret){
				printf("[Error] tcf_get_process_role ret:0x%08X\n",ret);
				ret = -1;
				goto out;
			}
			if(rls) show_role(rls,1);
		}
		goto out;
	}
out:
	if(sign) SM2_FREE(sign);
	if(idupdate) httc_free(idupdate);
	if(rlupdate) httc_free(rlupdate);
	tcf_free_process_ids(process_ids,test_num);
	tcf_free_process_roles(roles,test_num);
	return ret;
}

