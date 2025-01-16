#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sqlite3.h"
#include "public.h"
#include "scan_path.h"
#include "cJSON.h"

#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_policy.h"
#include "tcfapi/tcf_bmeasure.h"
#include "tcfapi/tcf_dmeasure.h"
#include "tcfapi/tcf_file_integrity.h"
#include "tcfapi/tcf_config.h"
#include "tcfapi/tcf_dev_protect.h"
#include "tcfapi/tcf_network_control.h"
#include "tcfapi/tcf_file_protect.h"

static uint64_t ht_get_replay_counter()
{
	int ret;
	uint64_t counter = 0;

	if ((ret=tcf_get_replay_counter(&counter)) != 0) {
		printf("tcf_get_replay_counter fail! ret: %08X\n", ret);
		return 0;
	}

	return counter + 1;
}

static int ht_sm2_sign(admin_t *admin, const unsigned char *data, int data_len, unsigned char **sig)
{
	unsigned int sig_len;
		
	return os_sm2_sign(data, (unsigned int)data_len, admin->prikey, PRIKEY_LENGTH, 
						admin->pubkey, PUBKEY_LENGTH, sig, &sig_len);
}

int ht_set_switch_whitelist(int on_off_flag )
{
	int ret, id_len = ID_LENGTH;
	unsigned char *sig = NULL;
	struct global_control_policy_update data;
	struct global_control_policy *policy = &data.policy;
	admin_t admin;
	char tpcm_id[ID_LENGTH + 1] = {0};


	do {
		tcf_get_tpcm_id(tpcm_id, &id_len);
		CHECK_FAIL(sdp_get_local_adminkey(&admin), );

		ret = tcf_get_global_control_policy(policy);
		if (ret != 0) {
			tools_log(HTTC_ERROR, "tcf_get_global_control_policy failed，ret=%08X.", ret);
			break;
		}

		policy->be_program_control = htobe32(on_off_flag);

		data.be_replay_counter = htobe64(ht_get_replay_counter());
		memcpy(data.tpcm_id, tpcm_id, MAX_TPCM_ID_SIZE);
		ht_sm2_sign(&admin, (unsigned char *)&data, sizeof(data), &sig);

		ret = tcf_set_global_control_policy(&data, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);
		if(ret != 0) {
			tools_log(HTTC_ERROR, "tcf_set_global_control_policy failed，ret=%08X.", ret);
			break;
		}
	} while (0);

	agent_free(sig);
	return ret;
}