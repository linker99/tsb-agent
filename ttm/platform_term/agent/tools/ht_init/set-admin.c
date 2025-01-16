
#include "cJSON.h"
#include "public.h"

#include "tcfapi/tcf_auth.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_tpcm_error.h"

admin_t g_admin;

uint64_t ht_init_get_replay_counter()
{
	int ret;
	uint64_t counter = 0;

	if ((ret=tcf_get_replay_counter(&counter)) != 0) {
		printf("tcf_get_replay_counter fail! ret: %08X\n", ret);
		return 0;
	}

	return counter + 1;
}

int ht_init_sm2_sign(admin_t *admin, const unsigned char *data, int data_len, unsigned char **sig)
{
	unsigned int sig_len;
		
	return os_sm2_sign(data, (unsigned int)data_len, admin->prikey, PRIKEY_LENGTH, 
						admin->pubkey, PUBKEY_LENGTH, sig, &sig_len);
}

int setadmin_get_local_adminkey(admin_t *admin)
{
	FILE *fp = NULL;
	char path[512] = {0};
	struct stat st;

	snprintf(path, sizeof(path)-1, "%s/etc/adminkey", HOME_PATH);

	stat(path, &st);
	if ((access(path, F_OK)) != 0 || (st.st_size != sizeof(*admin))){
		printf("adminkey file is not exist!\n");
		return HT_INIT_ERR_FILE;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		printf("read %s fail\n", path);
		return HT_INIT_ERR_FILE;
	}

	fread((void *)admin, 1, sizeof(*admin), fp);
	fclose(fp);
	return HT_INIT_OK;
}

int ht_init_setadmin_local()
{
    unsigned char *sig = NULL;
	int ret, id_len = ID_LENGTH;
	char tpcm_id[ID_LENGTH + 1] = {0};
	struct admin_cert_update item;

	tcf_get_tpcm_id(tpcm_id, &id_len);
	
	memset(&item, 0, sizeof(item));
	item.be_size = htobe32(sizeof(item));
	item.be_action = htobe32(POLICY_ACTION_SET);
	item.be_replay_counter = htobe64(ht_init_get_replay_counter());
	memcpy(item.tpcm_id, tpcm_id, ID_LENGTH);
	item.cert.be_cert_type = htobe32(CERT_TYPE_PUBLIC_KEY_SM2);
	item.cert.be_cert_len = htobe32(PUBKEY_LENGTH);
	sprintf(item.cert.name, UID_LOCAL);
	memcpy(item.cert.data, g_admin.pubkey, PUBKEY_LENGTH);

    ht_init_sm2_sign(&g_admin, (unsigned char *)&item, sizeof(item), &sig);
	/* 此处默认平台内部无授权信息，不需要签名 */
	ret = tcf_set_admin_cert(&item, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);
	if (ret != 0) {
		printf("set admin cert fail, ret=%08X\n", ret);
		return -1;
	}
    free(sig);

	return 0;
}

int ht_init_command_setadmin()
{	

	setadmin_get_local_adminkey(&g_admin);

	return ht_init_setadmin_local();
	
	return HT_INIT_OK;
}
