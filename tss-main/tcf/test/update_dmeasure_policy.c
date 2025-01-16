#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <httcutils/convert.h>
#include <httcutils/mem.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_dmeasure.h"
#include "crypto/sm/sm2_if.h"
#include "../src/tutils.h"


#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

void usage()
{
	printf ("\n"
			" Usage: ./update_dmeasure_policy [options]\n"
			" options:\n"
			"        -n <num>           - The number (0-3) <default 3>"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"    eg. ./update_dmeasure_policy -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_dmeasure_policy -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ch = 0;
	int ret = 0;
	int num = 3;

  	int keyStrLen = 0;
	char *keyStr = NULL;
	uint8_t privkey[32] = {0};
	int privkeyLen = 0;
	uint8_t pubkey[64] = {0};
	int pubkeyLen = 0;
	char * uid = NULL;

	int type = 1;
	int dminterval = 10000;
	struct timeval time;
	uint8_t *sign = NULL;
	uint32_t signlength = 0;
	uint64_t replay_counter = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t tpcm_id[MAX_TPCM_ID_SIZE] = {0};

	int policy_update_length = 0;
	struct dmeasure_policy_item_user item_user[3];
	struct dmeasure_policy_update *policy_update = NULL;

	while ((ch = getopt(argc, argv, "n:u:k:h")) != -1)
	{
		switch (ch) 
		{
			case 'n':
				num = atoi (optarg);
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
				httc_util_str2array (privkey, (uint8_t *)keyStr, TPCM_PRIVKEY_STR_LEN);
				privkeyLen = TPCM_PRIVKEY_STR_LEN / 2;
				//tcf_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, (uint8_t *)keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				//tcf_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}

	if ((num < 0) || (num > 3)){
		usage ();
		return -EINVAL;
	}

	if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
	}

	item_user[0].type = type;
	item_user[0].interval_milli = dminterval;
	item_user[0].name = "syscall_table";

	item_user[1].type = type;
	item_user[1].interval_milli = dminterval;
	item_user[1].name = "kernel_section";
	
	item_user[2].type = type;
	item_user[2].interval_milli = dminterval;
	item_user[2].name = "idt_table";

	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))){
		printf ("tcs_get_tpcm_id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	if (0 != (ret = tcf_prepare_update_dmeasure_policy (item_user, num,
			tpcm_id, tpcm_id_length, POLICY_ACTION_SET, replay_counter, &policy_update, &policy_update_length))){
	}

	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)policy_update,
				policy_update_length, privkey, 32, pubkey, 64, &sign ,&signlength))){
			printf ("Sign for dynamic policy failed!\n");
			goto out;
		}
		if (0 != (ret = os_sm2_verify (
				(const uint8_t *)policy_update, policy_update_length, pubkey, 64, sign, signlength))){
			printf ("Verify for dynamic policy failed!\n");
		}
	}
	
	if (0 != (ret = tcf_update_dmeasure_policy (policy_update, uid, auth_type, signlength, sign))){
		printf ("tcf_update_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	printf ("tcf_update_dmeasure_policy success\n");
out:
	if (policy_update) httc_free (policy_update);
	return ret;
}


