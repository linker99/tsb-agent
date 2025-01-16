#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "mem.h"
#include "debug.h"
#include "tutils.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_network_control.h"
#include "tcs_network_control_def.h"
#include "tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};

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
	int length = 0;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t *data = NULL;
	uint8_t *KeytStr = NULL;
	char *uid = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	
	struct network_control_update *update = NULL;
	struct network_config_item *policy = NULL;
	struct ip_config *items = NULL;
	uint64_t replay_counter;

	uint8_t switch_flags = 0;
	

	uint32_t action = 0; 
    uint32_t id;        
	uint32_t from;      
	uint32_t to;       
	uint32_t status;     
		

	if(argc < 15 || !(argc%2)){
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


	
	if(NULL == (data = httc_malloc(4096))){
		printf("[Error] Malloc error!\n");
		return -1;
	}	

	length = HTTC_ALIGN_SIZE(sizeof(struct network_config_item) + sizeof(struct ip_config),4);
	update = (struct network_control_update *)data;	
	
	update->be_size = htonl(sizeof(struct network_control_update));
	update->be_action = htonl(action);
	update->be_data_length = htonl(length);
	update->be_item_number = htonl(1);
	ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}
	



	update->be_replay_counter = htonll(replay_counter);
	policy = (struct network_config_item *)update->data;
	policy->be_total_num = htonl(1);
	policy->be_port_sw = switch_flags;


	items = policy->item;
	items->be_from = from;
	items->be_id = id;
	items->be_status = status;
	items->be_to = to;
	

	length += sizeof(struct network_control_update);
//	httc_util_dump_hex ("admin_auth_policy", update , length);

	if(KeytStr) ret = httc_sign_verify((const unsigned char *)update,length,privkey,32,pubkey,64,&sign,&signlen);

	if (ret){
		printf ("[Error] httc_sign_verify failed!\n");
		ret = -1;
		goto out;
	}
	
	ret = tcs_update_network_control_policy(update,uid,cert_type,signlen,sign);
	if(ret){
		printf("[Error] tcs_update_file_protect_policy ret:0x%08X\n",ret);
		ret = -1;
		goto out;
	}
	goto out;		

out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;

}



