#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "public.h"

#include "tcfapi/tcf_policy.h"
#include "tcsapi/tcs_auth_def.h"
#include "tcfapi/tcf_attest.h"

static char *program_name = NULL;
static char *command = NULL;
static char *switch_flag = NULL;

int usage()
{
	printf("Usage:  %s [COMMAND] [switch_flag]\n\n", program_name );
	printf("COMMAND:\n");
	printf("%s show								get policy switch.\n", program_name );
	printf("%s dmeasure  on/off					set dmeasure policy switch.\n", program_name );
	printf("%s smeasure  on/off					set smeasure policy switch.\n", program_name );

	printf("%s -h									print usage help information\n\n\n", program_name );

	exit(HT_HELP);
}

int sdp_get_local_adminkey(admin_t *admin)
{
	FILE *fp = NULL;
	char path[512] = {0};
	struct stat st;

	snprintf(path, sizeof(path)-1, "%s/etc/adminkey", HOME_PATH);

	stat(path, &st);
	if ((access(path, F_OK)) != 0 || (st.st_size != sizeof(*admin))){
		printf("file %s not exist or size error\n", path);
		return HT_ERR_EXIST;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		printf("read %s fail\n", path);
		return HT_ERR_FILE;
	}

	fread((void *)admin, 1, sizeof(*admin), fp);
	fclose(fp);
	return HT_OK;
}

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

int ht_set_smeasure_switch( int on_off_flag )
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
			printf("tcf_get_global_control_policy failed, ret=%08X.\n", ret);
			break;
		}

		policy->be_program_control = htobe32(on_off_flag);

		data.be_replay_counter = htobe64(ht_get_replay_counter());
		memcpy(data.tpcm_id, tpcm_id, MAX_TPCM_ID_SIZE);
		ht_sm2_sign(&admin, (unsigned char *)&data, sizeof(data), &sig);

		ret = tcf_set_global_control_policy(&data, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);
		if(ret != 0) {
			printf("tcf_set_global_control_policy failed,ret=%08X.\n", ret);
			break;
		}
	} while (0);

	printf("set smeasure switch success!\n");

	agent_free(sig);
	return ret;
}

int ht_set_dmeasure_switch( int on_off_flag )
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
			printf("tcf_get_global_control_policy failed, ret=%08X.\n", ret);
			break;
		}

		policy->be_dynamic_measure_on = htobe32(on_off_flag);

		data.be_replay_counter = htobe64(ht_get_replay_counter());
		memcpy(data.tpcm_id, tpcm_id, MAX_TPCM_ID_SIZE);
		ht_sm2_sign(&admin, (unsigned char *)&data, sizeof(data), &sig);

		ret = tcf_set_global_control_policy(&data, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);
		if(ret != 0) {
			printf("tcf_set_global_control_policy failed,ret=%08X.\n", ret);
			break;
		}
	} while (0);

	printf("set dmeasure switch success!\n");

	agent_free(sig);
	return ret;
}

int ht_show_global_policy_switch()
{
	int ret = 0;
	struct global_control_policy policy;

	ret = tcf_get_global_control_policy(&policy);
	if (ret != 0) {
		printf("tcf_get_global_control_policy failed, ret=%08X.\n", ret);
		return ret;
	}

	printf("smeausre swtich: %s\n", be32toh(policy.be_program_control) == 0 ? "OFF" : "ON" );
	printf("dmeasure switch: %s\n", be32toh(policy.be_dynamic_measure_on) == 0 ? "OFF" : "ON" );

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = HT_HELP;
	program_name = argv[0]; 
	if (argc < 2 ) {//入参检查
		usage();
		printf("invalid parameters specified\n");
		exit(1);
	}
	command = argv[1];
	if(strcmp(command, "show") == 0) {
		ret = ht_show_global_policy_switch();
	}else if(strcmp(command, "dmeasure") == 0) { //动态度量
		if(!argv[2])
		{
			return usage();
		}
		switch_flag = argv[2];
		if(strcmp(switch_flag, "on") == 0)
		{
			ret = ht_set_dmeasure_switch(1);
		} else if(strcmp(switch_flag, "off") == 0)
		{
			ret = ht_set_dmeasure_switch(0);
		}
	} else if(strcmp(command, "smeasure") == 0) { //静态度量
		if(!argv[2])
		{
			return usage();
		}
		switch_flag = argv[2];
		if(strcmp(switch_flag, "on") == 0)
		{
			ret = ht_set_smeasure_switch(1);
		} else if(strcmp(switch_flag, "off") == 0)
		{
			ret = ht_set_smeasure_switch(0);
		}
	}

	return ret == HT_HELP ? usage() : ret;
}