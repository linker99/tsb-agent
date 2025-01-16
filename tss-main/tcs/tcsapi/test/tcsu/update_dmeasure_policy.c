#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "mem.h"
#include "debug.h"
#include "tutils.h"
#include "convert.h"
#include "crypto/sm/sm2_if.h"
#include "tcs_auth.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_dmeasure.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

void usage()
{
	printf ("\n"
			" Usage: ./update_dmeasure_policy [options]\n"
			" options:\n"
			"        -d <interval>      - measure interval (Unit: millisecond <default: 10000>)\n"
			"        -o <operation>     - The operation (0-reset<default>; 1-add; 2-delete; 3-modify)\n"
			"        -n	<name>          - measure object name (syscall_table | kernel_section | idt_table | none)\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"        -k <key>           - The privkey string + pubkey string\n"
			"    eg. ./update_dmeasure_policy -d 10\n"
			"    eg. ./update_dmeasure_policy -d 10 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_dmeasure_policy -n syscall_table -d 10 -u dmeasure-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	char *dmname = NULL;
	uint32_t dminterval = 10;
	uint64_t replay_counter;
	int name_length = 0;
	
	uint8_t *keyStr = NULL;
  	int keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	int privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	int pubkeyLen = 0;

	int number = 0;
	uint8_t *policyData = NULL;
	uint8_t *sign = NULL;
	int signlength = 0;

	const char *uid = NULL;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	struct dmeasure_policy_update *dpolicy = NULL;
	struct dmeasure_policy_item *dpolicy_item = NULL;
	uint32_t operation = POLICY_ACTION_SET;
	
	if (NULL == (policyData = httc_malloc (1024))){
		perror ("Malloc for reference failure\n");
		return -1;
	}
	memset (policyData, 0, 1024);

	while ((ch = getopt(argc, argv, "n:d:u:k:o:h")) != -1)
	{
		switch (ch) 
		{
			case 'n':
				dmname = optarg;
				//printf ("dname: %s\n", dmname);
				break;
			case 'd':
				dminterval = atoi(optarg);	
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
				httc_util_dump_hex ("privkey", privkey, privkeyLen);
				httc_util_str2array (pubkey, keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				pubkeyLen = TPCM_PUBKEY_STR_LEN / 2;
				httc_util_dump_hex ("pubkey", pubkey, pubkeyLen);
				break;
			default:
				usage ();
				return -EINVAL;
		}
	}

	dpolicy = (struct dmeasure_policy_update *)policyData;
	if (dmname){
		if (strcmp (dmname, "none")){
			dpolicy_item = (struct dmeasure_policy_item *)dpolicy->data + number;
			dpolicy_item->be_type = htonl(1);
			dpolicy_item->be_interval_milli = htonl(dminterval);
			memcpy (dpolicy_item->object, dmname, strlen (dmname));
			number++;
		}
	}
	else {
		dpolicy_item = (struct dmeasure_policy_item *)dpolicy->data + number;
		dpolicy_item->be_type = htonl(1);
		dpolicy_item->be_interval_milli = htonl(dminterval);
		memcpy (dpolicy_item->object, "syscall_table", strlen ("syscall_table"));
		number++;
		
		dpolicy_item = (struct dmeasure_policy_item *)dpolicy->data + number;
		dpolicy_item->be_type = htonl(1);
		dpolicy_item->be_interval_milli = htonl(dminterval);
		memcpy (dpolicy_item->object, "kernel_section", strlen ("kernel_section"));
		number++;

		dpolicy_item = (struct dmeasure_policy_item *)dpolicy->data + number;
		dpolicy_item->be_type = htonl(1);
		dpolicy_item->be_interval_milli = htonl(dminterval);
		memcpy (dpolicy_item->object, "idt_table", strlen ("idt_table"));
		number++;
	}

	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}	
	
	dpolicy->be_size = htonl (sizeof (struct dmeasure_policy_update));
	dpolicy->be_action = htonl (operation);
	dpolicy->be_replay_counter = htonll(replay_counter);
	dpolicy->be_item_number = htonl (number);
	dpolicy->be_data_length = htonl (sizeof (struct dmeasure_policy_item) * number);

	if (0 != (ret = tcs_get_tpcm_id (dpolicy->tpcm_id, &tpcm_id_length))){
		printf ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		goto out;
	}

	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)dpolicy,
				sizeof (struct dmeasure_policy_update) + sizeof (struct dmeasure_policy_item) * number, privkey, 32, pubkey, 64, &sign ,&signlength))){
			printf ("Sign for dynamic policy failed!\n");
			goto out;
		}
		if (0 != (ret = os_sm2_verify ((const uint8_t *)dpolicy,
				sizeof (struct dmeasure_policy_update) + sizeof (struct dmeasure_policy_item) * number, pubkey, 64, sign, signlength))){
			printf ("Verify for dynamic policy failed!\n");
		}
	}

	if (0 != (ret = tcs_update_dmeasure_policy (dpolicy, uid, auth_type, signlength, sign))){
		printf ("[tcs_update_dmeasure_policy] ret: %d(0x%x)\n", ret, ret);
		ret = -1;
	}

out:
	if (sign) SM2_FREE(sign);
	if(policyData) httc_free(policyData);
	return ret;
}


