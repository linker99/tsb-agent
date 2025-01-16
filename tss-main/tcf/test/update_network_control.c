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
#include "tcsapi/tcs_network_control.h"
#include "tcsapi/tcs_network_control_def.h"
#include "tcfapi/tcf_network_control.h"
#include "tcsapi/tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"
#include "../src/tutils.h"


#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128
#define MAX_NUMBER		20


uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
uint8_t  *path[MAX_NUMBER] = {NULL};
uint32_t test_num = 1;
uint32_t sec_test_num = 1;
int type = 0;
int privi_type = 0;

uint8_t switch_flags = 0;
uint32_t id;        
uint32_t from;      
uint32_t to;       
uint32_t status;    

void usage()
{
	printf ("\n"
			" Usage: ./update_network_control_policy [options]\n"
			" options:\n"
			"        -w <switch_flags>     - NETWORK_PORT_SWITCH_CLOSE = 0,NETWORK_PORT_SWITCH_CLOSE=1, \n"
			"        -f <from>          - USER_START_PORT or IP \n"
			"        -d <id>          - USER_ID\n"
			"        -t <to>           - USER_START_PORT or IP\n"
			"        -s <status>           -  0bit--黑白名单标记位; 1bit--端口策略; 2bit--TCP标记; 3bit--UDP标记\n"
			"        -a <action>           - set:0 add:1 delete:2\n"
			"        -c <cert_type>      - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"    eg. ./update_network_control_policy -w 0 -d 1 -f 100  -t 200 -s 0x00000002  -a 0 -u file-protect-uid -k 396D6C567AC5B374C93980893C532F4123195B9D19B927B0A69B5D81745C1C3E8D19F78081B017AF0E6E52198FDCD334F651265CEE28F300ABC3FE6D668BD1987E79916EACEE2BCF74C34ADE8F5A137C5E4F61CE30A362B8DDCD85FCF13A573A\n"
			"    eg. ./update_network_control_policy -w 0 -d 2 -f 100  -t 200 -s 0x00000002  -a 1  -u file-protect-uid -k 396D6C567AC5B374C93980893C532F4123195B9D19B927B0A69B5D81745C1C3E8D19F78081B017AF0E6E52198FDCD334F651265CEE28F300ABC3FE6D668BD1987E79916EACEE2BCF74C34ADE8F5A137C5E4F61CE30A362B8DDCD85FCF13A573A\n"
			"\n");
}

void show_network_control_policy(struct network_config_item_user *policies, int num){

	int i = 0;
	int j = 0;
	int op = 0;
	int opt = 0;
	int number = 0;
	struct network_config_item_user *cur_item = NULL;
	struct ip_config_user *cur = NULL;

 	for (j = 0 ; j < num; j++){
		cur_item = (struct network_config_item_user *)((uint8_t *)policies + op);
		printf ("policies->port_sw: %s\n", cur_item->port_sw == 1 ? "NETWORK_SWITCH_OPEN" : "NETWORK_SWITCH_OFF");
		printf ("policies->be_total_num: %d\n",  (cur_item->total_num));
	
		number = (int)(cur_item->total_num);
		opt = 0;	
		for(i = 0;i < number; i++){
			cur = (struct ip_config_user *)((uint8_t *)cur_item->item + opt);
			printf ("be_from: %d\n",  (cur->from));
			printf ("be_to: %d\n",  (cur->to));
			printf ("be_id: %d\n",  (cur->id));
			printf ("be_status: %d\n", (cur->status));	
		
			printf("\n\n");
			opt += sizeof(struct ip_config);			
		}

		op += opt;
		op += sizeof(struct network_config_item);
		HTTC_ALIGN_SIZE(op,4);
		
		
	}
	
	//if(policies)  tcf_free_network_control_policy(policies,num);
}
int build_network_control_policy(struct network_config_item_user *policy, int num){

	int i = 0;
	int j = 0;

	for(;i < num; i++){
		policy[i].port_sw = switch_flags;
		policy[i].total_num = sec_test_num;
		if(NULL == (policy[i].item = httc_malloc(policy[i].total_num * sizeof(struct ip_config_user **)))){
			printf("[Error] Malloc error!\n");
			return -1;
		}
		//for(j = 0;j < sec_test_num; j++)
		{
			 
			if(NULL == (policy[i].item[0] = (struct ip_config_user *)httc_malloc(sizeof(struct ip_config_user)))){
				printf("[Error] Malloc error!\n");
				return -1;
			}
		

			(*(policy[i].item[0])).from=from;
			(*(policy[i].item[0])).id=id;
			(*(policy[i].item[0])).status=status;
			(*(policy[i].item[0])).to=to;

			// 	if(NULL == (policy[i].item[1] = (struct ip_config_user *)httc_malloc(sizeof(struct ip_config_user)))){
			// 	printf("[Error] Malloc error!\n");
			// 	return -1;
			// }

			// (*(policy[i].item[1])).from=from+1;
			// (*(policy[i].item[1])).id=id+1;
			// (*(policy[i].item[1])).status=status+1;
			// (*(policy[i].item[1])).to=to+1;
			
		}
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
	int opt = 1;
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
	uint64_t replay_counter;

    struct policy_version_user version;
	version.type=POLICY_TYPE_NETWORK_CONTROL;
	struct network_config_item_user *policy = NULL;
	struct network_control_update *update = NULL;
	int fplength = 0;
	

	if(argc < 3){
		usage();
		return -1;
	}


		while ((ch = getopt(argc, argv, "a:s:w:f:t:d:c:u:k:h")) != -1)
	{
		switch (ch) 
		{
			case 'c':
				cert_type = atoi(optarg);
				break;
			case 'u':
				uid = optarg;
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
			case 'w':
				switch_flags = (uint8_t)atoi(optarg);
				break;
			case 'f':
				from = atoi(optarg);
				break;
			case 't':
				to = atoi(optarg);
				break;
			case 'd':
				id = atoi(optarg);
				break;
			case 's':
				status = (uint8_t)atoi(optarg);
				break;
			case 'a':
				action = atoi(optarg);
				break;
				
			case 'h':
				usage ();
				break;
			default:
				usage ();
				return -1;
		}
	}
	
//printf("#from:%d\r\n",from);
//printf("#to:%d\r\n",to);

printf("#status:%d\r\n",status);
	if(opt == 0){

		policy = httc_malloc(test_num * sizeof (struct network_config_item_user));

		ret = build_network_control_policy(policy, test_num);
		if(ret) goto out;

//		show_network_control_policy(policy, test_num);
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		// if(httc_get_replay_counter(&replay_counter)){
		// 	printf("Error httc_get_replay_counter.\n");
		// 	ret = -1;
		// 	goto out;
		// }
		
			if(tcf_get_one_policy_version(&version)){
			printf("Error tcf_get_cdrom_config  \n");
			ret = -1;
			goto out;
		}
		replay_counter=version.major;
		replay_counter++;
		ret = tcf_prepare_update_network_control_policy(policy,test_num,tpcm_id,tpcm_id_length,action,replay_counter,
		&update,&fplength);		
		if(ret){
			printf("[Error] tcf_prepare_update_network_control_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		httc_util_dump_hex("update",(uint8_t *)update,fplength);
		goto out;
	}else if(opt == 1){
		
		policy = httc_malloc(test_num * sizeof (struct network_config_item_user));
		ret = build_network_control_policy(policy, test_num);
		if(ret) goto out;
		
	//show_network_control_policy(policy, test_num);
	
		ret = tcf_get_tpcm_id(tpcm_id, &tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_tpcm_id ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		
		// if(httc_get_replay_counter(&replay_counter)){
		// 	printf("Error httc_get_replay_counter.\n");
		// 	ret = -1;
		// 	goto out;
		// }
			if(tcf_get_one_policy_version(&version)){
			printf("Error tcf_get_cdrom_config  \n");
			ret = -1;
			goto out;
		}
		replay_counter=version.major;
		replay_counter++;
		
		ret = tcf_prepare_update_network_control_policy(policy,test_num,tpcm_id,tpcm_id_length,action,replay_counter,
		&update,&fplength);		

		
		if(ret){
			printf("[Error] tcf_prepare_update_network_control_policy ret:0x%08X\n",ret);
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

		ret = tcf_update_network_control_policy(update,uid,cert_type,signlen,sign);
			
		if(ret){
			printf("[Error] tcf_update_file_protect_policy ret:0x%08X\n",ret);
			ret = -1;
			goto out;
		}
		goto out;
		}

out:
	if(sign) SM2_FREE(sign);
	if(update) httc_free(update);
		
	tcf_free_network_control_policy(policy,test_num);
		
	return ret;
}
