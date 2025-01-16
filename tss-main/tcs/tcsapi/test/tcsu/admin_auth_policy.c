#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tutils.h"
#include "tcs_constant.h"
#include "tcs_attest.h"
#include "tcs_auth.h"
#include "tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	(SM2_PRIVATE_KEY_SIZE * 2)
#define TPCM_PUBKEY_STR_LEN		(SM2_PUBLIC_KEY_SIZE * 2)
#define MAX_NUMBER 20
//#define ZERO_TEST

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};

uint32_t policy_number = 1;
uint32_t object_id[MAX_NUMBER] = {1};
uint32_t policy_flags[MAX_NUMBER] = {0};
uint32_t user_or_group[MAX_NUMBER] = {0};
uint32_t admin_auth_type[MAX_NUMBER] = {ADMIN_AUTH_POLICY_AND_CERT};
unsigned char name[MAX_NUMBER][MAX_PROCESS_NAME_LENGTH] = {0};

static void usage ()
{
	printf ("\n"
			" Usage: ./admin_auth_policy -c <cert_type> -k <key> -n <name> -o <operation> -t <opt_type> -i <id>\n"			
			"		                     -a <admin_auth_type> -f <flag> -u <user or group> -N <number>\n"
			"		 -U <uid>      - The uid for match cert\n"
			"		 -c <cert_type>      - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"		 -k <key>            - The privkey string + pubkey string\n"
			"		 -n <name>           - The name of process or role\n"
			"		 -o <operation>      - (default)0:tcs_set_admin_auth_policies\n"
			"		                                1:tcs_get_admin_auth_policies\n"	
			"		 -t <opt_type>       - (default)0:set 1:add 2:replace 3:delete\n"
			"		 -i <id>             - The object id\n"
			"		 -a <admin_auth_type>           0:ADMIN_AUTH_POLICY_NO_REQUIRE_CERT\n"
			"		                       (default)1:ADMIN_AUTH_POLICY_REQUIRE_CERT\n"
			"		 -f <flag>           - The policy_flags\n"
			"		 -u <U or G>         - User or Group id\n"
			"		 -N <number>         - The number of policy defalut(1)\n"
			"		 eg. ./admin_auth_policy -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -n root -o 0 -t 0 -i 1 -a 1 -f 1 -u 0\n"
			"		     ./admin_auth_policy -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -o 0 -t 0 -N 2 -n one -i 1 -a 1 -f 0x1 -u 0 -n two -i 2 -a 1 -f 0xb -u 0\n\n");
}

int build_admin_auth_policys(int argc,char **argv){

	int ch = 0;
	int n = 0, i = 0, a = 0, f = 0, u = 0;
	unsigned char *curname = NULL;
	
	while ((ch = getopt(argc, argv, "n:i:a:f:u:")) != -1)
	{	
		switch (ch) 
		{
			case 'n':
				curname = optarg;
				memcpy(name[n],curname,strlen((const char *)curname));
				n++;
				break;
			case 'i':
				object_id[i] = atoi(optarg);
				i++;
				break;
			case 'a':
				admin_auth_type[a] = atoi(optarg);
				a++;
				break;
			case 'f':
				policy_flags[f] = strtol (optarg, NULL, 16);
				f++;
				break;
			case 'u':
				user_or_group[u] = atoi(optarg);
				u++;
				break;
			default:
				usage ();
				return -1;
		}
	}
	return 0;
}
void build_admin_auth_policy(struct admin_auth_policy_update *update, int *length){
	
#ifndef ZERO_TEST
	int i = 0;
	update->be_number = htonl(policy_number);
	for(; i < policy_number ; i++){
		update->policies[i].be_object_id = htonl(object_id[i]);
		update->policies[i].be_admin_auth_type = htonl(admin_auth_type[i]);
		update->policies[i].be_policy_flags = htonl(policy_flags[i]);
		update->policies[i].be_user_or_group = htonl(user_or_group[i]);
		memcpy(update->policies[i].process_or_role,name[i],strlen((const char *)name[i]));
	}
#else
	update->be_number = htonl(0);
#endif
	*length = sizeof(struct admin_auth_policy_update) + (ntohl(update->be_number) * sizeof(struct admin_auth_policy));

}

void show_admin_auth_policy(struct admin_auth_policy *policies, int num){	
	int i = 0;
	for(;i < num; i++){
		printf("================admin_auth_policy:%d================\n",i);
		printf ("policies->be_object_id: 0x%08X\n", ntohl ((policies + i)->be_object_id));
		printf ("policies->be_admin_auth_type: 0x%08X\n", ntohl ((policies + i)->be_admin_auth_type));
		printf ("policies->be_policy_flags: 0x%08X\n", ntohl ((policies + i)->be_policy_flags));
		printf ("policies->be_user_or_group: 0x%08X\n", ntohl ((policies + i)->be_user_or_group));
		printf ("policies->process_or_role: %s\n", (policies + i)->process_or_role);		
	}
	if(policies) httc_free(policies);
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
	int cert_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int opt_type = POLICY_ACTION_SET;
	int length = 0;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t *data = NULL;
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	unsigned char *curname = NULL;
	const char *uid = NULL;
	struct admin_auth_policy_update *update = NULL;
	struct admin_auth_policy *list = NULL;
	uint64_t replay_counter = 0;

	if(argc < 3 || !(argc%2)){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "U:c:k:n:o:t:i:a:f:u:N:h")) != -1)
	{
		switch (ch) 
		{
			case 'U':
				uid = optarg;
				break;
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
			case 'n':
				curname = optarg;
				memcpy(name[0],curname,strlen((const char *)curname));
				break;
			case 'o':
				opt = atoi(optarg);
				break;
			case 't':
				opt_type = atoi(optarg);
				break;
			case 'i':
				object_id[0] = atoi(optarg);
				break;
			case 'a':
				admin_auth_type[0] = atoi(optarg);
				break;
			case 'f':
				policy_flags[0] = strtol (optarg, NULL, 16);
				break;
			case 'u':
				user_or_group[0] = atoi(optarg);
				break;
			case 'N':
				policy_number = atoi(optarg);
				if(policy_number > MAX_NUMBER){
					printf("Max test policy number is %d\n",MAX_NUMBER);
					return -1;
				}
				ret = build_admin_auth_policys(argc,argv);
				if(ret) return ret;
				optind = argc;
				break;
			case 'h':
				usage ();
				break;
			default:
				usage ();
				return -1;
		}
	}


	if(NULL == (data = httc_malloc(4096))){
		printf("[Error] Malloc error!\n");
		return -1;
	}
#if 1
	if(opt == 0){
		
		update = (struct admin_auth_policy_update *)data;
		build_admin_auth_policy(update, &length);	
		update->be_action = htonl(opt_type);
		if(httc_get_replay_counter(&replay_counter)) goto out;	
		ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		update->be_replay_counter = htonll(replay_counter);
//		httc_util_dump_hex ("admin_auth_policy", update , length);

		ret = httc_sign_verify((const unsigned char *)update,length,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
		
		ret = tcs_set_admin_auth_policies(update,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_set_admin_auth_policies ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
	}else if(opt == 1){
		ret = tcs_get_admin_auth_policies(&list,&num);
		if(ret){
			printf("[Error] tcs_get_admin_auth_policies ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		show_admin_auth_policy(list,num);
		goto out;
	}
#endif
out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;

}

