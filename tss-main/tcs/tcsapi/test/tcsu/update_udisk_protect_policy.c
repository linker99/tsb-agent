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
#include "tcs_udisk_protect.h"
#include "tcs_udisk_protect_def.h"
#include "tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};

void usage()
{
	printf ("\n"
			" Usage: ./update_udisk_protect_policy [options]\n"
			" options:\n"
			"        -T <access_ctr>          -READ_ONLY = 1, WRITE_ONLY = 2\n"
			"        -a <action>           - set:0 add:1 delete:2\n"
			"        -c <cert_type>      - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"        -g <guid>           - guid string\n"
			"    eg. ./update_udisk_protect_policy   -T 2 -g guidtest -u udisk-protect-uid -k 396D6C567AC5B374C93980893C532F4123195B9D19B927B0A69B5D81745C1C3E8D19F78081B017AF0E6E52198FDCD334F651265CEE28F300ABC3FE6D668BD1987E79916EACEE2BCF74C34ADE8F5A137C5E4F61CE30A362B8DDCD85FCF13A573A\n"
			"    eg. ./update_udisk_protect_policy   -T 1 -g guidtest2 -u udisk-protect-uid -k 396D6C567AC5B374C93980893C532F4123195B9D19B927B0A69B5D81745C1C3E8D19F78081B017AF0E6E52198FDCD334F651265CEE28F300ABC3FE6D668BD1987E79916EACEE2BCF74C34ADE8F5A137C5E4F61CE30A362B8DDCD85FCF13A573A\n"
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
	
	struct udisk_protect_update *update = NULL;
	struct udisk_conf_item *policy = NULL;

	uint64_t replay_counter;

	uint8_t measure_flags = 0;
	uint8_t type = 0;
	uint32_t privi_type  = 0;
	uint32_t action = 0; 
    unsigned char *guid = NULL;
		

	// if(argc < 15 || !(argc%2)){
	// 	usage();
	// 	return -1;
	// }

	if(argc < 0){
		usage();
		return -1;
	}
	while ((ch = getopt(argc, argv, "a:T:c:u:g:k:h")) != -1)
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

			case 'T':
				type = (uint8_t)atoi(optarg);
				break;

			case 'a':
				action = atoi(optarg);
				break;
			case 'g':
				guid = optarg;
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

	length = HTTC_ALIGN_SIZE(sizeof(struct udisk_conf_item),4);
	update = (struct udisk_protect_update *)data;	
	
	update->be_size = htonl(sizeof(struct udisk_protect_update));
	update->be_action = htonl(action);
	update->be_data_length = htonl(length);
	update->be_item_number = htonl(1);
	ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}
	// if(tcf_get_cdrom_config(&replay_counter)){
	// 		printf("Error tcf_get_cdrom_config  replay_counter:%ld\n",replay_counter);
	// 		ret = -1;
	// 		goto out;
	// 	}
		
	// replay_counter++;
	update->be_replay_counter = htonll(replay_counter);
	policy = (struct udisk_conf_item *)update->data;
	policy->access_ctrl=type;
	memcpy(policy->guid,guid,__GUID_LENGTH);
	length += sizeof(struct udisk_protect_update);

	

	if(KeytStr) ret = httc_sign_verify((const unsigned char *)update,length,privkey,32,pubkey,64,&sign,&signlen);

	if (ret){
		printf ("[Error] httc_sign_verify failed!\n");
		ret = -1;
		goto out;
	}


	ret = tcs_update_udisk_protect_policy(update,uid,cert_type,signlen,sign);
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



