#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include "mem.h"
#include "debug.h"
#include "tutils.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_process.h"
#include "tcs_process_def.h"
#include "tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
uint8_t *role_name = NULL;

static void usage ()
{
	printf ("\n"
			" Usage: ./role -c <cert_type> -k <key> -u <uid> -n <name> -o <operation> [-t] <type>\n"
			"        -c <cert_type>	     - The cert_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -k <key>            - The privkey string + pubkey string\n"
			"        -u <uid>	         - The uid\n"
			"        -n <name>	         - The role name\n"
			"        -o <operation>	     - (default)0:tcs_update_process_roles\n"
			"                                       1:tcs_get_process_roles\n"
			"        -t <operation_type> - (default)0:set 1:add 2:delete 3:repleace\n"
			"    eg. ./role -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -n role -o 0 -t 0\n\n");
}

void show_role(struct process_role *roles,int num){
	
	int i = 0;
	int j = 0;
	int pop = 0;
	int op = 0;
	int name_number = 0;
	unsigned char name[128];
	struct process_role *pcur = NULL;
	struct role_member *cur = NULL;
	for(;i < num;i++){
		pcur = (struct process_role *)((uint8_t *)roles + pop);
		printf("================RUN:%d================\n",i);
		memset(name,0,128);
		op = ntohl(pcur->be_name_length);
		memcpy(name,pcur->members,op);
		printf("name:%s\n",name);
		name_number = ntohl(pcur->be_members_number);
		for(j = 0;j < name_number;j++){
			cur = (struct role_member *)(pcur->members + op);
			memset(name,0,128);
			memcpy(name,cur->name,cur->length);
			printf("%d:%s\n",j,name);
			op += cur->length + sizeof(struct role_member);
		}
		pop += HTTC_ALIGN_SIZE(op + sizeof(struct process_role), 4);
		printf("\n\n");		 
	}
	if(roles) httc_free(roles);
}

void build_role(struct process_role_update *role, int *length){

	int op = 0;
	unsigned char *member_name = "member";
	struct process_role *currole = NULL;
	struct role_member *curmem = NULL;

	role->be_size = htonl(sizeof(struct process_role_update));
#ifndef ZERO_TEST
	role->be_item_number = htonl(1);
	
	currole = (struct process_role *)role->data;	
	op = strlen((const char *)role_name);
	currole->be_name_length = htonl(op);
	currole->be_members_number = htonl(1);
	memcpy(currole->members,role_name,op);

	curmem = (struct role_member *)(currole->members + op);
	curmem->length = (uint8_t)strlen((const char *)member_name);
	memcpy(curmem->name,member_name,strlen((const char *)member_name));

	currole->be_members_length = HTTC_ALIGN_SIZE(sizeof(struct role_member) + curmem->length , 4);
	role->be_data_length = sizeof(struct process_role) + currole->be_members_length + op;	
	*length = sizeof(struct process_role_update) + role->be_data_length;
	currole->be_members_length = htonl(currole->be_members_length);
#else
	role->be_item_number = htonl(0);
	role->be_data_length = 0;
	*length = sizeof(struct process_role_update);

#endif	
	role->be_data_length = htonl(role->be_data_length);
	
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

	int ch = 0;
	int opt = 0;
	int ret = 0;
	int num = 0;
	int length = 0;
	int cert_type = CERT_TYPE_PUBLIC_KEY_SM2;	
	int opt_type = POLICY_ACTION_SET;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t *data = NULL;	
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	const char *uid = NULL;
	struct process_role_update *update = NULL;
	struct process_role *roles = NULL;
	uint64_t replay_counter;

	if(argc < 3 || !(argc%2)){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "c:k:u:n:o:t:h")) != -1)
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
				role_name = optarg;
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


	if(NULL == (data = httc_malloc(4096))){
		printf("[Error] Malloc error!\n");
		return -1;
	}
	if(opt == 0){
		update = (struct process_role_update *)data;
		build_role(update,&length);
		update->be_action = htonl(opt_type);
		
	
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			return -1;
		}	
			ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		update->be_replay_counter = htonll(replay_counter);

		ret = httc_sign_verify((const unsigned char *)update,length,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
		
		ret = tcs_update_process_roles(update,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_update_process_roles ret:0x%08x\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_update_process_roles success!\n");
		
	}else if(opt == 1){
		
		num = 4096/sizeof(char *);
		ret = tcs_get_process_roles(&roles,&num,&length);
//		httc_util_dump_hex ("roles", roles , length);
		if(ret){
			printf("[Error] tcs_get_process_roles ret:0x%08x\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_get_process_roles success!\n");
		show_role(roles,num);
		goto out;
	}

out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;

}

