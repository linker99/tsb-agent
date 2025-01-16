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
#include "tcsapi/tcs_dev_protect.h"
#include "tcsapi/tcs_dev_protect_def.h"
#include "tcfapi/tcf_dev_protect.h"
#include "tcfapi/tcf_dev_version.h"
#include "tcsapi/tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"
#include "../src/tutils.h"


#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128
#define MAX_NUMBER		20


uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};

uint32_t test_num = 1;
uint32_t sec_test_num = 2;
int type = 1;
int measure_flags = 1;
int privi_type = 0;

static void usage ()
{
	printf ("\n"
			" Usage: ./update_dev_protect_policy -c <cert_type> -k <key> -u <uid> [-N] <number> -p <path> -o <operation> [-a] <action>\n"
			"        -c <cert_type>      - The cert_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -k <key>            - The privkey string + pubkey string\n"
			"        -u <uid>            - The uid\n"
			"        -T <type>          - FILE_WRITE_PROTECT = 0, FILE_READ_PROTECT = 1\n"				
			"        -N <number>         - The number of policy(default 1)\n"
			"        -o <operation>      - (default)0:tcf_prepare_update_cdrom_protect_policy\n"
			"                                       1:tcf_update_cdrom_protect_policy\n"                                
			"        -a <action> - (default)0:set 1:add 2:delete\n"
			"    eg. ./update_dev_protect_policy -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -p /usr/lib -o 0 -a 0\n"
			"        ./update_dev_protect_policy -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -N 2 -n /usr/lib/one /usr/lib/two -o 0 -a 0\n\n");
}



void show_cdrom_protect_policy(struct cdrom_protect_item *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
		printf ("policy[%d] measure_flags: %s\n",i, policy[i].be_flags == 1 ? "CDROM_PROTECT" : "CDROM_NO_PROTECT");
		
		

		printf("\n\n");
	}
}



int build_cdrom_protect_policy(struct cdrom_protect_item *policy, int num){

	int i = 0;
	for(;i < num; i++){
		policy[i].be_flags =type;

	}
	return 0;
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
	int action = POLICY_ACTION_SET;	
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	const char *uid = NULL;
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	uint64_t replay_counter=0;

	struct cdrom_protect_item *policy = NULL;
	struct cdrom_protect_update *update = NULL;
	struct policy_version_user version;
	version.type=POLICY_TYPE_DEV_PROTECT;
	int fplength = 0;
	

	if(argc < 3){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "T:t:f:c:k:u:N:p:o:a:h")) != -1)
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

			case 'T':
				type = atoi(optarg);
				break;

			case 'N':
				test_num = atoi(optarg);
				break;
			case 'o':
				opt = atoi(optarg);
				break;
			case 'a':
				action = atoi(optarg);
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
	
		policy = httc_malloc(test_num * sizeof (struct cdrom_protect_item));
		ret = build_cdrom_protect_policy(policy, test_num);
		if(ret) goto out;

//		show_cdrom_protect_policy(policy, test_num);
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		
		if(tcf_get_one_policy_version(&version)){
			printf("Error tcf_get_cdrom_config  replay_counter:%ld\n",replay_counter);
			ret = -1;
			goto out;
		}
		replay_counter=version.major;
		replay_counter++;
		
		 ret = tcf_prepare_update_cdrom_protect_policy(policy,test_num,tpcm_id,tpcm_id_length,action,replay_counter,
		 &update,&fplength);		
		if(ret){
			printf("[Error] tcf_prepare_update_cdrom_protect_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		httc_util_dump_hex("update",(uint8_t *)update,fplength);
		goto out;
	}else if(opt == 1){
		
		policy = httc_malloc(test_num * sizeof (struct cdrom_protect_item));
		ret = build_cdrom_protect_policy(policy, test_num);
		if(ret) goto out;
	
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		
		if(tcf_get_one_policy_version(&version)){
			printf("Error tcf_get_cdrom_config  replay_counter:%ld\n",replay_counter);
			ret = -1;
			goto out;
		}
		replay_counter=version.major;
		replay_counter++;
	   
		ret = tcf_prepare_update_cdrom_protect_policy(policy,test_num,tpcm_id,tpcm_id_length,action,replay_counter,
		&update,&fplength);		
		if(ret){
			printf("[Error] tcf_prepare_update_cdrom_protect_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		ret = httc_sign_verify((const unsigned char *)update,fplength,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
//		httc_util_dump_hex ((const char *)"rl22222", rlupdate , rllength);
		ret = tcf_update_cdrom_protect_policy(update,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcf_update_cdrom_protect_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
		}

out:
	if(sign) SM2_FREE(sign);
	if(update) httc_free(update);
	tcf_free_dev_protect_policy(policy);
	return ret;
}

