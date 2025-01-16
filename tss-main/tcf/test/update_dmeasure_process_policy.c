#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "httcutils/mem.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"
#include "crypto/sm/sm2_if.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_auth_def.h"
#include "tcsapi/tcs_policy_def.h"
#include "tcfapi/tcf_dmeasure.h"
#include "../src/tutils.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

void usage()
{
	printf ("\n"
			" Usage: ./update_dmeasure_process_policy [options]\n"
			" options:\n"
			"		 -d <interval>		- measure interval (Unit: millisecond <default: 10000>)\n"
			"        -o <operation>		- The operation (0-reset<default>; 1-add; 2-delete; 3-modify)\n"
			"	 	 -n	<num>			- object number\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"		 -k <key>			- The privkey string + pubkey string\n"
			"    eg. ./update_dmeasure_process_policy -o 0 -d 10000 -t \n"
			"    eg. ./update_dmeasure_process_policy -d 10 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_dmeasure_process_policy -n syscall_table -d 10 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

#define OBJECT_ID_MAX_LENGTH	32

int main(int argc, char **argv){

	int i = 0;
	int ch = 0;
	int ret = 0;
	int ops = 0;
    uint8_t hash_buf[32] = {0};
	uint32_t dminterval = 1000;
	uint64_t replay_counter = 0;
	int max_len = 0;
	int obj_type = PROCESS_DMEASURE_OBJECT_ID_PROCESS;
	char *obj_id_name = NULL;
    int obj_id_name_len = 0;
	
	uint8_t *keyStr = NULL;
  	int keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	int privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	int pubkeyLen = 0;

	int number = 0;
	uint8_t *sign = NULL;
	int signlength = 0;

	const char *uid = NULL;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	char tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	int update_len = 0;
	struct dmeasure_process_policy_update *update = NULL;
	struct dmeasure_process_item_user *policy_item = NULL;
	uint32_t operation = POLICY_ACTION_SET;

	while ((ch = getopt(argc, argv, "n:d:u:k:o:h")) != -1)
	{
		switch (ch) 
		{
			case 'n':
				number = atoi (optarg);
				//printf ("number: %d\n", number);
				break;
			case 'd':
				dminterval = atoi (optarg);	
				//printf ("dminterval: %d\n", dminterval);
				break;
			case 'o':
				operation = atoi (optarg);
				break;
			case 'u':
				uid = optarg;
				break;				
			case 'k':
				keyStr = optarg;	
				keyStrLen = strlen(keyStr);
				if ((TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN) != keyStrLen){
					printf ("Invalid key string!\n");
					return -EINVAL;
				}
				httc_util_str2array (privkey, keyStr, TPCM_PRIVKEY_STR_LEN);
				privkeyLen = TPCM_PRIVKEY_STR_LEN / 2;
				//httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				//httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}

	if (number){
		if (NULL == (policy_item = (struct dmeasure_process_item_user *)httc_calloc (number, sizeof (struct dmeasure_process_item_user)))){
			perror ("Malloc for reference failure\n");
			return -1;
		}
	}

	for (i = 0; i < number; i++){
		policy_item[i].object_id_type = i % (PROCESS_DMEASURE_OBJECT_ID_HASH + 1);
		policy_item[i].sub_process_mode = PROCESS_DMEASURE_MODE_MEASURE;
		policy_item[i].old_process_mode = PROCESS_DMEASURE_MODE_MEASURE;
		policy_item[i].share_lib_mode = PROCESS_DMEASURE_MODE_NON_MEASURE;
		policy_item[i].measure_interval = dminterval;
		if (policy_item[i].object_id_type == PROCESS_DMEASURE_OBJECT_ID_HASH){
			policy_item[i].object_id_length = DEFAULT_HASH_SIZE;
			if (NULL == (policy_item[i].object_id = httc_malloc (policy_item[i].object_id_length))){
				httc_util_pr_error ("Malloc for policy_item[%d].object_id failure\n", i);
				return -1;
			}
			memset (policy_item[i].object_id, 0x12, DEFAULT_HASH_SIZE);
		}else{
			policy_item[i].object_id_length = sizeof ("object_i") + 3;
			if (NULL == (policy_item[i].object_id = httc_malloc (policy_item[i].object_id_length))){
				httc_util_pr_error ("Malloc for policy_item[%d].object_id failure\n", i);
				return -1;
			}
			sprintf (policy_item[i].object_id, "object_id%02x", i&0xFF);
		}
	}

	if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
	}	

	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))){
		httc_util_pr_error ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	if (0 != (ret = tcf_prepare_update_dmeasure_process_policy (policy_item,
			number, tpcm_id, tpcm_id_length, operation, replay_counter, &update, &update_len))){
			httc_util_pr_error ("tcf_prepare_update_dmeasure_process_policy id error: %d(0x%x)\n", ret, ret);
			goto out;
	}
	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)update,
				update_len, privkey, 32, pubkey, 64, &sign ,&signlength))){
			httc_util_pr_error ("Sign for dynamic policy failed!\n");
			goto out;
		}
		if (0 != (ret = os_sm2_verify ((const uint8_t *)update,
				update_len, pubkey, 64, sign, signlength))){
			httc_util_pr_error ("Verify for dynamic policy failed!\n");
		}
	}

	if (0 != (ret = tcf_update_dmeasure_process_policy (update, uid, auth_type, signlength, sign))){
		printf ("[tcs_update_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		ret = -1;
	}

out:
	if (sign) SM2_FREE(sign);
	if (update) httc_free(update);
	if (policy_item) tcf_free_dmeasure_process_policy (policy_item, number);
	return ret;
}



