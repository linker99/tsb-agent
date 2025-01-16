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
#include "tcs_protect.h"

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128

void usage()
{
	printf ("\n"
			" Usage: ./update_ptrace_protect_policy [options]\n"
			" options:\n"
			"	 	 -o	<operation>	    - operation (0-set<default>; 2-delete)\n"
			"        -u <uid>           - The user ID (for match cert)\n"
			"		 -k <key>			- The privkey string + pubkey string\n"
			"    eg. ./update_ptrace_protect_policy -u ptrace-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"    eg. ./update_ptrace_protect_policy -n 3 -u ptrace-uid -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A\n"
			"\n");
}

int main(int argc, char **argv){

	int i = 0;
	int ch = 0;
	int ret = 0;
	int ops = 0;
	
	uint8_t *keyStr = NULL;
  	int keyStrLen = 0;
	uint8_t  privkey[32] = {0};
  	int privkeyLen = 0;
	uint8_t  pubkey[64] = {0};
  	int pubkeyLen = 0;

	int ptracer_number = 2;
	int non_tracee_number = 3;
	int max_len = 0;
	const char *uid = NULL;
	uint8_t *sign = NULL;
	int signlength = 0;
	int auth_type = CERT_TYPE_PUBLIC_KEY_SM2;
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	struct ptrace_protect_update *update = NULL;
	struct ptrace_protect *policy_item = NULL;
	struct process_name *proc_names = NULL;
	uint32_t operation = POLICY_ACTION_SET;
	uint64_t replay_counter;

	while ((ch = getopt(argc, argv, "u:k:o:h")) != -1)
	{
		switch (ch) 
		{
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

	max_len = sizeof (struct ptrace_protect_update)
		+ MAX_NAME_LENGTH * (ptracer_number + non_tracee_number);

	if (NULL == (update = (struct ptrace_protect_update *)httc_malloc (max_len))){
		perror ("Malloc for reference failure\n");
		return -1;
	}
	memset (update, 0, max_len);

	policy_item = &update->data[0];

	if (POLICY_ACTION_DELETE != operation){
		policy_item->be_ptrace_protect = htonl (1);
		policy_item->be_ptracer_number = htonl (ptracer_number);
		policy_item->be_non_tracee_number = htonl (non_tracee_number);
		for (i = 0; i < (ptracer_number + non_tracee_number); i++){
			proc_names = (struct process_name *)(policy_item->process_names + ops);
			snprintf (proc_names->prcess_names, MAX_NAME_LENGTH, "ptrace_process%d", i);
			proc_names->be_name_length = htonl (sizeof ("ptrace_process0"));
			ops += sizeof (struct process_name) + HTTC_ALIGN_SIZE (sizeof ("ptrace_process0"), 4);
		}
		policy_item->be_total_length = htonl (ops);
	}

	
	
	if(httc_get_replay_counter(&replay_counter)){
		printf("Error httc_get_replay_counter.\n");
		ret = -1;
		goto out;
	}

	update->be_size = htonl (sizeof (struct ptrace_protect_update));
	update->be_action = htonl (POLICY_ACTION_SET);
	update->be_replay_counter = htonll(replay_counter);
	update->be_data_length = htonl (sizeof (struct ptrace_protect) + ops);
	if (0 != (ret = tcs_get_tpcm_id (update->tpcm_id, &tpcm_id_length))){
		printf ("Get tpcm id error: %d(0x%x)\n", ret, ret);
		ret = -1;
		goto out;
	}

	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)update,
				sizeof (struct ptrace_protect_update) + ops, privkey, 32, pubkey, 64, &sign ,&signlength))){
			printf ("Sign for ptrace protect failed!\n");
			goto out;
		}
		httc_util_dump_hex ("sign", sign, signlength);
		if (0 != (ret = os_sm2_verify ((const uint8_t *)update,
				sizeof (struct ptrace_protect_update) + ops, pubkey, 64, sign, signlength))){
			printf ("Verify for ptrace protect failed!\n");
		}
	}

	if (0 != (ret = tcs_update_ptrace_protect_policy (update, uid, auth_type, signlength, sign))){
		printf ("[tcs_update_ptrace_protect_policy] ret: %d(0x%x)\n", ret, ret);
		ret = -1;
	}

out:
	if (sign) SM2_FREE(sign);
	if (update) httc_free((update));
	return ret;
}


