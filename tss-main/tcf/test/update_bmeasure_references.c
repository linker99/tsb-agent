#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcsapi/tcs_error.h"
#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_bmeasure.h"
#include "crypto/sm/sm2_if.h"
#include "../src/tutils.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

void usage()
{
	printf ("\n"
			" Usage: ./update_bmeasure_references [options]\n"
			" options:\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"		 -k <key>			- The privkey string + pubkey string\n"
			"    eg. ./update_bmeasure_references\n"
			"    eg. ./update_bmeasure_references -u bmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

int main (int argc, char **argv)
{
	int i;
	int ch = 0;
	int num = 0;
	int ret = 0;
	char *uid = NULL;
	
  	int keyStrLen = 0;
	char *keyStr = NULL;
	uint8_t privkey[32] = {0};
	int privkeyLen = 0;
	uint8_t pubkey[64] = {0};
	int pubkeyLen = 0;

	struct timeval time;
	int action = POLICY_ACTION_SET;
	uint64_t replay_counter = 0;
	int ref_update_length = 0;
	uint8_t *sign = NULL;
	uint32_t signlength = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	uint8_t tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	struct boot_ref_item_user *item = NULL;
	struct boot_measure_record_user *boot_records = NULL;
	struct boot_references_update *ref_update = NULL;

	while ((ch = getopt(argc, argv, "u:k:h")) != -1)
	{
		switch (ch) 
		{
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
				httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, (uint8_t *)(keyStr + TPCM_PRIVKEY_STR_LEN), TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}
	
	if (0 != (ret = tcf_get_boot_measure_records (&boot_records, &num))){
		httc_util_pr_error ("tcf_get_boot_measure_records error: %d(0x%x)\n", ret, ret);
		return -1;
	}
	//httc_util_pr_dev ("tcf_get_boot_measure_records okay!\n");
	if (NULL == (item = httc_calloc (num, sizeof (struct boot_ref_item_user)))){
		httc_util_pr_error ("No mem for boot ref user data!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}

	for (i = 0; i < num; i++){
		item[i].hash_length = boot_records[i].hash_length;
		item[i].hash_number = 1;
		item[i].stage = boot_records[i].stage;
		item[i].is_control = 0;
		item[i].is_enable = 1;
		item[i].hash = &boot_records[i].hash[0];
		item[i].name = boot_records[i].name;
	}

	if(httc_get_replay_counter(&replay_counter)){
			printf("Error httc_get_replay_counter.\n");
			ret = -1;
			goto out;
	}

	//httc_util_pr_dev ("httc_get_replay_counter okay!\n");
	if (0 != (ret = tcf_get_tpcm_id (tpcm_id, &tpcm_id_length))){
		printf ("tcs_get_tpcm_id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}
	
	//httc_util_pr_dev ("tcf_get_tpcm_id okay!\n");
	if (0 != (ret = tcf_prepare_update_boot_measure_references (item, num,
			tpcm_id, tpcm_id_length, action, replay_counter, &ref_update, &ref_update_length))){
			printf ("tcf_prepare_update_boot_measure_references error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	//httc_util_pr_dev ("tcf_prepare_update_boot_measure_references okay!\n");
	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)ref_update,
				ref_update_length, privkey, 32, pubkey, 64, &sign ,&signlength))){
			printf ("Sign for bmeasure reference failed!\n");
			goto out;
		}
		if (0 != (ret = os_sm2_verify (
				(const uint8_t *)ref_update, ref_update_length, pubkey, 64, sign, signlength))){
			printf ("Verify for bmeasure reference failed!\n");
		}
	}

	if (0 != (ret = tcf_update_boot_measure_references (ref_update, uid, auth_type, signlength, sign))){
		printf ("tcf_update_boot_measure_references error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}
	printf ("update_bmeasure_reference_test success\n");

out:
	if (item) httc_free (item);
	if (ref_update) httc_free (ref_update);
	if (boot_records) tcf_free_boot_measure_records (boot_records, num);
	return ret;
}

