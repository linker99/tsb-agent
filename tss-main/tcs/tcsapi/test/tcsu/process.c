#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tutils.h"
#include "tcs_constant.h"
#include "tcs_attest.h"
#include "tcs_process.h"
#include "tcs_process_def.h"
#include "crypto/sm/sm2_if.h"

enum{
	CERT_TYPE_NONE,
	CERT_TYPE_PUBLIC_KEY_SM2,
	CERT_TYPE_PASSWORD_32_BYTE,
	CERT_TYPE_X501_SM2,
};

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

uint8_t  privkey[32] = {0};
uint8_t  pubkey[64] = {0};
uint8_t *name = NULL;

static void usage ()
{
	printf ("\n"
			" Usage: ./process -c <cert_type> -k <key> -u <uid> -n <name> -o <operation> [-t] <type>\n"
			"        -c <cert_type>      - The cert_type (default)1:SM2 2:HMAC 3:X501_SM2\n"
			"        -k <key>            - The privkey string + pubkey string\n"
			"        -u <uid>            - The uid\n"
			"        -n <name>           - The name of process or role\n"
			"        -o <operation>      - (default)0:tcs_update_process_identity\n"
			"                                       1:tcs_get_process_ids\n"
			"        -t <operation_type> - (default)0:set 1:add 2:delete 3:modify\n"
			"    eg. ./process -c 1 -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -u 123123 -n identity -o 0 -t 0\n\n");
}

void build_process_identity(struct process_identity_update *id,int *idlength){

	struct process_identity *item = NULL;
	id->be_size = htonl(sizeof(struct process_identity_update));	
#ifndef ZERO_TEST
	id->be_item_number = htonl(1);
	item = (struct process_identity *)id->data;
	item->name_length = (uint8_t)strlen((const char *)name);
	item->specific_libs = (uint8_t)1;
	item->be_hash_length = htons((uint16_t)(DEFAULT_HASH_SIZE));
	item->be_lib_number = htons((uint16_t)(1));
	sm3(name,strlen((const char *)name),item->data);
	memset(item->data + DEFAULT_HASH_SIZE ,8,DEFAULT_HASH_SIZE);
//	memset(item->data ,'1',DEFAULT_HASH_SIZE);
//	memset(item->data + DEFAULT_HASH_SIZE ,'2',DEFAULT_HASH_SIZE);
	memcpy(item->data + 2*DEFAULT_HASH_SIZE,name,item->name_length);
	id->be_data_length = htonl(HTTC_ALIGN_SIZE(sizeof(struct process_identity) + 2*DEFAULT_HASH_SIZE + strlen((const char *)name), 4));
#else
	id->be_item_number = htonl(0);
	id->be_data_length = 0;
#endif
	*idlength = sizeof(struct process_identity_update) + ntohl(id->be_data_length);

}

void show_process(struct process_identity *ids,int num){

	int i = 0;
	int j = 0;
	int op = 0;
	int hash_len = 0;
	struct process_identity *cur = NULL;
	
	for(;i < num; i++){
		cur = (struct process_identity *)((uint8_t *)ids + op);
		printf("================RUN:%d================\n",i);
		printf ("ids[%d] name: %s\n",i, cur->data + (1 + ntohs(cur->be_lib_number)) * ntohs(cur->be_hash_length));
		printf ("ids[%d] specific_libs: %s\n",i, cur->specific_libs == 0 ? "USE" : "UNUSE");
		printf ("ids[%d] lib number: %d\n",i, (uint32_t)ntohs(cur->be_lib_number));
		hash_len = (int)ntohs(cur->be_hash_length);
		for(j = 0; j < ntohs(cur->be_lib_number) + 1;j++){
			printf("[%d-%d]\n",i,j);
			httc_util_dump_hex ("HASH IS", cur->data + (j * hash_len) , hash_len);
		}
		op += HTTC_ALIGN_SIZE(hash_len * (1 + ntohs(cur->be_lib_number))  + cur->name_length + sizeof(struct process_identity), 4);
		
	}
	if(ids) httc_free(ids);
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
	int idlength = 0;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t *data = NULL;
	const char *uid = NULL;
	uint8_t *KeytStr = NULL;
	int keystrlen = 0;
	uint8_t *sign = NULL;
	uint32_t signlen = 0;
	struct process_identity_update *update = NULL;
	struct process_identity *ids = NULL;
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
				name = optarg;
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
		
		update = (struct process_identity_update *)data;
		build_process_identity(update, &idlength);
		update->be_action = htonl(opt_type);
		
	
		if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
		}
		ret = tcs_get_tpcm_id(update->tpcm_id, &tpcm_id_length);
		update->be_replay_counter = htonll(replay_counter);
		
		ret = httc_sign_verify((const unsigned char *)update,idlength,privkey,32,pubkey,64,&sign,&signlen);
		if (ret){
			printf ("[Error] httc_sign_verify failed!\n");
			ret = -1;
			goto out;
		}
		
		ret = tcs_update_process_identity(update,uid,cert_type,signlen,sign);
		if(ret){
			printf("[Error] tcs_update_process_identity ret:0x%08x\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_update_process_identity success!\n");
		goto out;
	}else if(opt == 1){
		num = 4096/sizeof(char *);
		ret = tcs_get_process_ids(&ids,&num,&tpcm_id_length);
		if(ret){
			printf("[Error] tcs_get_process_ids ret:0x%08x\n",ret);
			ret = -1;
			goto out;
		}
		printf("tcs_get_process_ids success!\n");
		show_process(ids,num);
		goto out;
	}

out:
	if(sign) SM2_FREE(sign);
	if(data) httc_free(data);
	return ret;

}



