#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include <httcutils/mem.h>
#include <httcutils/debug.h>
#include <httcutils/convert.h>
#include "crypto/sm/sm2_if.h"
#include "tcsapi/tcs_auth_def.h"
#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_protect.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_error.h"
#include "../src/tutils.h"


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
	int name_length = 0;
	
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
	char tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	int tpcm_id_length = MAX_TPCM_ID_SIZE;
	int update_len = 0;
	struct ptrace_protect_update *update = NULL;
	struct ptrace_protect_user *policy_user = NULL;
	uint32_t operation = POLICY_ACTION_SET;
	uint64_t replay_counter = 0;

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
					httc_util_pr_error ("Invalid key string!\n");
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

	if (POLICY_ACTION_DELETE != operation){
		if (NULL == (policy_user = httc_malloc (sizeof (struct ptrace_protect_user)
							+ sizeof (char *) * (ptracer_number + non_tracee_number)))){
			httc_util_pr_error ("No mem for policy_user_item data!\n");
			ret = TCF_ERR_NOMEM;
			goto out;
		}
		policy_user->ptracer_names = (void*)policy_user + sizeof (struct ptrace_protect_user);
		policy_user->non_tracee_names = (void*)policy_user + sizeof (struct ptrace_protect_user) + sizeof (char*) * ptracer_number;
		policy_user->is_ptrace_protect = 1;
		policy_user->ptracer_number = ptracer_number;
		policy_user->non_tracee_number = non_tracee_number;
		for (i = 0; i < ptracer_number; i++){
			name_length = sizeof ("ptrace_process%d");
			if (NULL == (policy_user->ptracer_names[i] = httc_malloc (name_length))){
				httc_util_pr_error ("No mem for ptracer_names[%d]\n", i);
				tcf_free_ptrace_protect_policy (policy_user);
				goto out;
			}
			snprintf (policy_user->ptracer_names[i], name_length, "ptrace_process%d", i);
		}
		for (i = 0; i < non_tracee_number; i++){
			name_length = sizeof ("ptrace_process%d");
			if (NULL == (policy_user->non_tracee_names[i] = httc_malloc (name_length))){
				httc_util_pr_error ("No mem for ptracer_names[%d]\n", i);
				tcf_free_ptrace_protect_policy (policy_user);
				goto out;
			}
			snprintf (policy_user->non_tracee_names[i], name_length, "ptrace_process%d", i);
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

	if (0 != (ret = tcf_prepare_ptrace_protect_policy (policy_user,
			tpcm_id, tpcm_id_length, POLICY_ACTION_SET, replay_counter, &update, &update_len))){
			httc_util_pr_error ("tcf_prepare_ptrace_protect_policy id error: %d(0x%x)\n", ret, ret);
			goto out;
	}

	if (keyStr){
		if (0 != (ret = os_sm2_sign((const uint8_t *)update, update_len, privkey, 32, pubkey, 64, &sign ,&signlength))){
			httc_util_pr_error ("Sign for ptrace protect failed!\n");
			goto out;
		}
		if (0 != (ret = os_sm2_verify ((const uint8_t *)update, update_len, pubkey, 64, sign, signlength))){
			httc_util_pr_error ("Verify for ptrace protect failed!\n");
		}
	}
	if (0 != (ret = tcf_update_ptrace_protect_policy (update, uid, auth_type, signlength, sign))){
		httc_util_pr_error ("[tcf_update_ptrace_protect_policy] ret: %d(0x%x)\n", ret, ret);
		ret = -1;
	}

out:
	if (sign) SM2_FREE(sign);
	if (update) httc_free(update);
	if (policy_user) tcf_free_ptrace_protect_policy (policy_user);
	return ret;
}


