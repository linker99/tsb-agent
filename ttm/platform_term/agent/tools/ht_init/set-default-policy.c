#include "cJSON.h"
#include "sqlite3.h"
#include "public.h"

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
#include "tcfapi/tcf_tnc.h"
#include "tcsapi/tcs_tnc_def.h"


static struct dmeasure_policy_item_user dm_default_policy[] = {
	{
		.name = "kernel_section",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	},
	{
		.name = "syscall_table",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	},
	{
		.name = "idt_table",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	},
	{
		.name = "module_list",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	},
	{
		.name = "filesystem",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	},
	{
		.name = "network",
		.interval_milli = DEFAULT_DMEASURE_TIME,
	}
};

char *sdp_format_json(cJSON *array, int action)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *array2 = cJSON_Duplicate(array, 1);
	
	cJSON_AddItemToObject(root, "action", cJSON_CreateNumber(action));
	cJSON_AddItemToObject(root, "policy", array2);

	char *str = cJSON_PrintUnformatted(root);

	cJSON_Delete(root);
	return str;
}

int sdp_whitelist_get_fromDB(int *row, int *column, char ***data)
{
	char db_path[512] = {0};
	sqlite3 *db = NULL;
	char *sql = "select * from whitelist order by hash";
	char *errmsg = NULL;

	snprintf(db_path, sizeof(db_path)-1, "%s/db/whitelist.db", HOME_PATH);

	if (sqlite3_open(db_path, &db) != SQLITE_OK) {
		printf("open db %s fail\n", db_path);
		return -1;
	}

	if (sqlite3_get_table(db, sql, data, row, column, &errmsg) != SQLITE_OK) {
		printf("get data fail, errmsg: %s\n", errmsg);
		sqlite3_close(db);
		agent_free(errmsg);
		return -1;
	}

	sqlite3_close(db);
	return 0;
}

int sdp_whitelist_set_sign(admin_t *admin, struct file_integrity_item_user *items,
								int item_count, int action, cJSON *array)
{
	int ret, size, id_len = ID_LENGTH;
	unsigned long long counter;
	char *json_str = NULL;
	unsigned char *sig = NULL;
	char tpcm_id[ID_LENGTH + 1] = {0};
	struct file_integrity_update *references = NULL;

	tcf_get_tpcm_id(tpcm_id, &id_len);
	json_str = sdp_format_json(array, action);
	counter = ht_init_get_replay_counter();
	
	//printf("get replay counter: %llu, whitelist policy number: %d\n", counter, item_count);
	
	ret = tcf_prepare_update_file_integrity(items, item_count, tpcm_id,	MAX_TPCM_ID_SIZE,
											action, counter, &references, &size);
	if(ret != 0) {
		printf("prepare smeasure policy fail, ret=%08X\n", ret);
		ret = HT_INIT_ERR_TCF;
		goto clean;
	}

	ht_init_sm2_sign(admin, (unsigned char *)references, size, &sig);
	ret = tcf_update_file_integrity(references, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, 
						SIG_LENGTH, sig, (unsigned char *)json_str, strlen(json_str) + 1);
	if(ret != 0) {
		printf("update smeasure policy fail, ret=%08X\n", ret);
		ret = HT_INIT_ERR_TCF;
	}

clean:

	agent_free(sig);
	agent_free(json_str);
	agent_free(references);
	return ret;
}

int sdp_whitelist_set_policy(admin_t *admin, int total_count, int column, char **data)
{
	int ret = 0, left_count = total_count;
	int i, j, index = column, action = POLICY_ACTION_SET;
	const char *last_hash = "";
	struct file_integrity_item_user *items = NULL;
	
	items = (struct file_integrity_item_user *)agent_calloc(sizeof(*items) * ONCE_MAX_COUNT);
	if (items == NULL) {
		printf("malloc fail\n");
		return HT_INIT_ERR_MALLOC;
	}
	
	while (left_count > 0) {
		int once_count;
		cJSON *json_array;
		once_count = (left_count > ONCE_MAX_COUNT) ? ONCE_MAX_COUNT : left_count;

		json_array = cJSON_CreateArray();

		for(i = 0, j = 0; i < once_count; i++, index += 4) {
			cJSON *json_one;
			json_one = cJSON_CreateObject();
			cJSON_AddNumberToObject(json_one, "source", atoi(data[index + 3]));
			cJSON_AddStringToObject(json_one, "hash", data[index + 2]);
			cJSON_AddStringToObject(json_one, "path", data[index + 1]);
			cJSON_AddStringToObject(json_one, "guid", data[index]);

			/* 如果与上一个hash不同，才新增items赋值 */
			if (strcmp(data[index + 2], last_hash) != 0) {
				items[j].is_enable = 1;
				items[j].is_control = 1;
				items[j].hash_length = HASH_LENGTH;
				items[j].hash = agent_calloc(HASH_LENGTH);
				str_to_binary(data[index + 2], items[j].hash, HASH_LENGTH);

				j++;
			}
			
			last_hash = data[index + 2];
			cJSON_AddItemToArray(json_array, json_one);
		}

		ret = sdp_whitelist_set_sign(admin, items, j, action, json_array);
		action = POLICY_ACTION_ADD;

		for (i = 0; i < j; i++) {
			agent_free(items[i].hash);
		}
		cJSON_Delete(json_array);

		if (ret != HT_INIT_OK) {
			break;
		}

		left_count -= once_count;
	}
	
	agent_free(items);
	sqlite3_free_table(data);
	return ret;
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
		return HT_INIT_ERR_EXIST;
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

int ht_init_sdp_global()
{
	int ret, id_len = ID_LENGTH;
	unsigned char *sig = NULL;
	char tpcm_id[ID_LENGTH + 1] = {0};
	struct global_control_policy_update data;
	struct global_control_policy *p = &data.policy;
	admin_t admin;
	
	tcf_get_tpcm_id(tpcm_id, &id_len);
	CHECK_FAIL(sdp_get_local_adminkey(&admin), );

	data.be_replay_counter = htobe64(ht_init_get_replay_counter());
	memcpy(data.tpcm_id, tpcm_id, ID_LENGTH);

	p->be_size = htobe32(sizeof(struct global_control_policy));
	p->be_boot_measure_on = htobe32(0);
	p->be_program_measure_on = htobe32(1);
	p->be_dynamic_measure_on = htobe32(1);
	p->be_program_control = htobe32(1);
	p->be_process_dmeasure_interval = htobe32(DEFAULT_DMEASURE_TIME);
	p->be_boot_control = htobe32(0);
	p->be_tsb_flag1 = htobe32(0);
	p->be_tsb_flag2 = htobe32(0);
	p->be_tsb_flag3 = htobe32(0);
	p->be_program_measure_mode = htobe32(PROCESS_MEASURE_MODE_TCS_MEASURE);
	p->be_measure_use_cache = htobe32(1);
	p->be_dmeasure_max_busy_delay = htobe32(300);
	p->be_process_dmeasure_ref_mode = htobe32(PROCESS_DMEASURE_REF_START);
	p->be_process_dmeasure_match_mode = htobe32(PROCESS_DMEASURE_MATCH_HASH_ONLY);
	p->be_program_measure_match_mode = htobe32(PROCESS_MEASURE_MATCH_HASH_ONLY);
	p->be_process_dmeasure_lib_mode = htobe32(PROCESS_DMEASURE_MODE_NON_MEASURE);
	p->be_process_verify_lib_mode = htobe32(PROCESS_VERIFY_MODE_DEFAULT);
	p->be_process_dmeasure_sub_process_mode = htobe32(PROCESS_DMEASURE_MODE_MEASURE);
	p->be_process_dmeasure_old_process_mode = htobe32(PROCESS_DMEASURE_MODE_MEASURE);

	ht_init_sm2_sign(&admin, (unsigned char *)&data, sizeof(data), &sig);
	ret = tcf_set_global_control_policy(&data, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);

	agent_free(sig);
	return ret;
}

int ht_init_sdp_dmeasure()
{
	int ret, ref_len, id_len = ID_LENGTH;
	int dm_default_count = sizeof(dm_default_policy) / sizeof(dm_default_policy[0]);
	unsigned char *sig = NULL;
	char tpcm_id[ID_LENGTH + 1] = {0};
	struct dmeasure_policy_update *reference = NULL;
	admin_t admin;

	tcf_get_tpcm_id(tpcm_id, &id_len);
	CHECK_FAIL(sdp_get_local_adminkey(&admin), );
	
	ret = tcf_prepare_update_dmeasure_policy(&dm_default_policy[0], dm_default_count,
											tpcm_id, MAX_TPCM_ID_SIZE,
											POLICY_ACTION_SET, ht_init_get_replay_counter(),
											&reference, &ref_len);
	if (ret != 0) {
		printf("prepare dmeasure reference fail, ret=%08X\n", ret);
		return HT_INIT_ERR_TCF;
	}

	ht_init_sm2_sign(&admin, (unsigned char *)reference, ref_len, &sig);
	
	ret = tcf_update_dmeasure_policy(reference, UID_LOCAL, CERT_TYPE_PUBLIC_KEY_SM2, SIG_LENGTH, sig);
	if (ret != 0) {
		printf("update dmeasure reference fail, ret=%08X\n", ret);
	}

	agent_free(sig);
	agent_free(reference);
	return ret;
}

int ht_init_sdp_whitelist()
{
	int row, column;
	char **data = NULL;
	admin_t admin;
	
	CHECK_FAIL(sdp_get_local_adminkey(&admin), );

	if (sdp_whitelist_get_fromDB(&row, &column, &data) < 0) {
		return HT_INIT_ERR_DB;
	}
	
	return sdp_whitelist_set_policy(&admin, row, column, data);
}

int ht_init_sdp_all()
{
	CHECK_FAIL(ht_init_sdp_global(), );
	CHECK_FAIL(ht_init_sdp_dmeasure(), );
	CHECK_FAIL(ht_init_sdp_whitelist(), );
	
	return HT_INIT_OK;
}

int ht_init_command_setdefaultpolicy(int argc, char **argv)
{
	if (argc != 1)
		return HT_INIT_HELP;

	const char *command = argv[0];
	
	if (strcmp(command, "global") == 0) {
		return ht_init_sdp_global();
	} else if (strcmp(command, "dmeasure") == 0) {
		return ht_init_sdp_dmeasure();
	} else if (strcmp(command, "whitelist") == 0) {
		return ht_init_sdp_whitelist();
	} else if (strcmp(command, "all") == 0) {
		return ht_init_sdp_all();
	}

	return HT_INIT_HELP;
}
