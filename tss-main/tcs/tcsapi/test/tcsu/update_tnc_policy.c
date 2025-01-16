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
#include "tcs_tnc.h"
#include "tcs_tnc_def.h"
#include "tcs_auth_def.h"
#include "crypto/sm/sm2_if.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
const char *server_ip =  "1.1.1.1";
uint16_t server_port = 22;

void usage()
{
	printf ("\n"
			" Usage: ./update_tnc_policy [options]\n"
			" options:\n"
			"        -m <mode>      - Control mode for tnc 0:uncontrol(default)  1:control all \n"
			"        -e <encrypt>     - Message encryption authentication or not 0:no(default) 1:yes\n"
			"        -t <testify>          - Is it confirmed by management center 0:no(default) 1:yes\n"
			"        -r <report>          - Report trusted authentication failure to management center or not 0:no(default) 1:yes\n"
			"        -s <status>          - Report session status to management center or not 0:no(default) 1:yes\n"
			"        -d <data>           - Session expiration time(seconds),0:no expired(default)\n"
			"        -n <number>           - Number of exceptions\n"
			"        -a <agreement>           - udp(2) or tcp(1)\n"
			"        -i <ip>           - Peer address 0:all\n"
			"        -I <ip>           - Local address 0:all\n"
			"        -p <port>           - Peer port 0:all\n"
			"        -P <port>           - Local port 0:all\n"
			"        -c <cert_type>      - The auth_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"    eg. ./update_tnc_policy -n 1 -a 0 -i 0 -I 0 -p 22 -P 22 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_tnc_policy -m 1 -e 1 -t 1 -r 1 -s 1 -d 3600 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -n 2 -a 6 -i 0 -I 0 -p 22 -P 22 -a 17 -i 0 -I 0 -p 16 -P 16\n"
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




static int build_tnc_policy_items(struct tnc_policy_item **items, int number, int argc, char **argv){

	int ch = 0;
	int x = 0;
	uint32_t protocol = 0;
	int a = 0, b = 0, c = 0, d = 0, e = 0;
	
	if(NULL == (*items = (struct tnc_policy_item *)httc_malloc(number * sizeof(struct tnc_policy_item)))){
		printf("[Error] Malloc error!\n");
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "a:i:I:p:P:")) != -1)
	{
		switch (ch) 
		{
			case 'a':
//				printf("a:%d\n",a);
				(*items + a)->be_protocol = htonl(atoi(optarg));
				a++;
				break;
			case 'i':
//				printf("b:%d\n",b);
				x = atoi(optarg);
				if(x != 0){
					(*items + b)->be_remote_ip =  (uint32_t)inet_addr(optarg);
				}else{
					(*items + b)->be_remote_ip = x;
				}
				b++;
				break;
			case 'I':
//				printf("c:%d\n",c);
				x = atoi(optarg);
				if(x != 0){
					(*items + c)->be_local_ip =  (uint32_t)inet_addr(optarg);
				}else{
					(*items + c)->be_local_ip = x;
				}
				c++;
				break;
			case 'p':
//				printf("d:%d\n",d);
				(*items + d)->be_remote_port = htons((uint16_t)atoi(optarg));
				d++;
				break;
			case 'P':
//				printf("e:%d\n",e);
				(*items + e)->be_local_port = htons((uint16_t)atoi(optarg));
				e++;
				break;
			default:
				usage ();
				return -1;
		}
	}
	return 0;
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
	
	struct tnc_policy_update *update = NULL;
	struct tnc_policy *policy = NULL;
	struct tnc_policy_item *items = NULL;
	uint64_t replay_counter;

	uint16_t control_mode = 0;
	uint8_t  encrypt_auth = 0;
	uint8_t  server_testify = 0;
	uint8_t  report_auth_fail = 0;
	uint8_t  report_session = 0;
	uint32_t session_expire = 0;
	uint32_t exception_number = 0;	

	if(argc < 17 || !(argc%2)){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "m:e:t:r:s:d:a:c:u:k:n:h")) != -1)
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
			case 'm':
				control_mode = (uint16_t)atoi(optarg);
				break;
			case 'e':
				encrypt_auth = (uint8_t)atoi(optarg);
				break;
			case 't':
				server_testify = (uint8_t)atoi(optarg);
				break;
			case 'r':
				report_auth_fail = (uint8_t)atoi(optarg);
				break;
			case 's':
				report_session = (uint8_t)atoi(optarg);
				break;
			case 'd':
				session_expire = atoi(optarg);
				break;			
			case 'n':
				exception_number = atoi(optarg);
				
				ret = build_tnc_policy_items(&items,exception_number,argc,argv);			
				if(ret) goto out;
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

	length = sizeof(struct tnc_policy) + exception_number * sizeof(struct tnc_policy_item);
	update = (struct tnc_policy_update *)data;
	
	update->be_size = htonl(sizeof(struct tnc_policy_update));
	update->be_action = htonl(POLICY_ACTION_SET);
	update->be_data_length = htonl(length);
	ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}
	
	update->be_replay_counter = htonll(replay_counter);
	policy = (struct tnc_policy *)update->policy;
	policy->be_server_ip = (uint32_t)inet_addr(server_ip);
	policy->be_server_port = htons(server_port);
	policy->be_control_mode = htons(control_mode);
	policy->encrypt_auth = encrypt_auth;
	policy->server_testify = server_testify;
	policy->report_auth_fail = report_auth_fail;
	policy->report_session = report_session;
	policy->be_session_expire = htonl(session_expire);
	policy->be_exception_number = htonl(exception_number);
	
	memcpy(policy->exceptions,items,exception_number * sizeof(struct tnc_policy_item));

	length += sizeof(struct tnc_policy_update);
//	httc_util_dump_hex ("admin_auth_policy", update , length);

	if(KeytStr) ret = httc_sign_verify((const unsigned char *)update,length,privkey,32,pubkey,64,&sign,&signlen);

	if (ret){
		printf ("[Error] httc_sign_verify failed!\n");
		ret = -1;
		goto out;
	}
	
	ret = tcs_update_tnc_policy(update,uid,cert_type,signlen,sign);
	if(ret){
		printf("[Error] tcs_update_tnc_policy ret:0x%08X\n",ret);
		ret = -1;
		goto out;
	}
	goto out;		

out:
	if(sign) SM2_FREE(sign);
	if(items) httc_free(items);
	if(data) httc_free(data);
	return ret;

}



