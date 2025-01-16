#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_error.h"
#include "tcsapi/tcs_bmeasure.h"
#include "tcfapi/tcf_bmeasure.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_notice.h"
#include "tutils.h"


/*
 * 	准备更新动态度量启动基准库
 */		
int tcf_prepare_update_boot_measure_references(
		const struct boot_ref_item_user *references,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,	uint64_t replay_counter,
		struct boot_references_update **obuffer,int *olen)
{
	int i = 0;
	int ret = 0;
	int ref_opt = 0;
	int name_length = 0;
	int item_size = 0;
	int hash_total_length = 0;
	struct boot_ref_item *ref = NULL;
	struct boot_references_update *ref_update = NULL;

	if ((num && !references) || !tpcm_id || !olen)	return TCF_ERR_PARAMETER;
	
	if (tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id_length is too long (%d > %d)\n", tpcm_id_length, MAX_TPCM_ID_SIZE);
		return TCF_ERR_INPUT_EXCEED;
	}

	if (NULL == (ref_update = httc_malloc (sizeof (struct boot_references_update) + MAX_BOOT_REFERENCE_ITEM_SIZE * num))){
		httc_util_pr_error ("No mem for ref update data!\n");
		return TCF_ERR_NOMEM;
	}
	memset (ref_update, 0, sizeof (struct boot_references_update) + MAX_BOOT_REFERENCE_ITEM_SIZE * num);
		
	for (i = 0; i < num; i ++){
		ref = (struct boot_ref_item *)(ref_update->data + ref_opt);
		if (!references[i].name || !references[i].hash){
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		if ((references[i].hash_number < 0) || (references[i].hash_number > MAX_BOOT_HASH_VERSION_NUMBER)){
			httc_util_pr_error ("Invalid hash version number: %d\n", references[i].hash_number);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		if (references[i].hash_length != DEFAULT_HASH_SIZE){
			httc_util_pr_error ("Invalid hash_length: %d\n", references[i].hash_length);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		if (references[i].extend_size && !references[i].extend_buffer){
			httc_util_pr_error ("extend_size: %d, extend_buffer: %p\n", references[i].extend_size, references[i].extend_buffer);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		if (references[i].extend_buffer 
				&& ((references[i].extend_size <= 0)
					|| (references[i].extend_size > MAX_BOOT_EXTERN_SIZE))){
			httc_util_pr_error ("Invalid extend_size: %d\n", references[i].extend_size);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		
		name_length = strlen ((const char *)references[i].name) + 1;
		if (name_length > MAX_PATH_LENGTH){
			httc_util_pr_error ("Invalid name_length: %d\n", name_length);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		hash_total_length = references[i].hash_length * references[i].hash_number;
		item_size = sizeof (struct boot_ref_item) + hash_total_length
					+ HTTC_ALIGN_SIZE (references[i].extend_size + name_length, 4);
		if ((ref_opt + item_size) > MAX_BOOT_REFERENCE_ITEM_SIZE * num){
			httc_util_pr_error ("Invalid item data\n");
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}

		ref->be_hash_length = htons (references[i].hash_length);
		if (!is_bool_value_legal(references[i].is_enable)){
			httc_util_pr_error ("Invalid item data, is_enable:%d, not in (ture,false)\n", references[i].is_enable);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		if (!is_bool_value_legal(references[i].is_control)){
			httc_util_pr_error ("Invalid item data, is_control:%d, not in (ture,false)\n", references[i].is_control);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		}
		ref->be_flags = htons ((references[i].is_enable << BOOT_REFERENCE_FLAG_ENABLE)
							| (references[i].is_control << BOOT_REFERENCE_FLAG_CONTROL));
		ref->be_name_length = htons (name_length);
		ref->be_hash_number = htons (references[i].hash_number);

		if ((references[i].stage < 0) || (references[i].stage > ((1 << (sizeof(ref->be_stage)*8)) - 1))){
			httc_util_pr_error ("Invalid stage : %d\n", references[i].stage);
			httc_free (ref_update);
			return TCF_ERR_PARAMETER;
		} 
		
		ref->be_stage = htons (references[i].stage);
		ref->be_extend_size = htons (references[i].extend_size);

		memcpy (ref->data, references[i].hash, references[i].hash_length * references[i].hash_number); /** hash */
		if (references[i].extend_buffer) memcpy (ref->data + hash_total_length, references[i].extend_buffer, references[i].extend_size); /** extern data */
		memcpy (ref->data + hash_total_length + references[i].extend_size, references[i].name, name_length); /** name */
		ref_opt += item_size;		
	}

	ref_update->be_size = htonl (sizeof (struct boot_references_update));
	ref_update->be_action = htonl (action);
	ref_update->be_replay_counter = htonll (replay_counter);
	ref_update->be_item_number = htonl (num);
	ref_update->be_data_length = htonl (ref_opt);
	memcpy (ref_update->tpcm_id, tpcm_id, tpcm_id_length);

	*obuffer = ref_update;
	*olen = sizeof (struct boot_references_update) + ref_opt;
	return ret;
}

// boot measure reference interface
/*
 * 	更新启动度量基准库
 * 	设置。
 */
int tcf_update_boot_measure_references(struct boot_references_update *references,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth)
{
	int ret = 0;
	ret = tcs_update_boot_measure_references (references, uid, auth_type, auth_length, auth);
	if(ret) return ret;
	httc_write_version_notices (htonll (references->be_replay_counter), POLICY_TYPE_BMEASURE_REF);

	return ret;
}

/*
 * 	获取启动度量基准库
 */
int tcf_get_boot_measure_references(struct boot_ref_item_user **references,int *num)
{
	int i;
	int ret = 0;
	int length = 0;
	char *buf = NULL;
	int item_size = 0;
	int ref_item_opt = 0;
	int hash_total_length = 0;
	int name_length = 0;
	int extend_size = 0;

	struct boot_ref_item *ref_item = NULL;
	struct boot_ref_item *ref_item_data = NULL;
	struct boot_ref_item_user *ref_user = NULL;

	if (0 != (ret = tcs_get_boot_measure_references (&ref_item_data, num, &length))){
		httc_util_pr_error ("tcs_get_boot_measure_references error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	if (NULL == (ref_user = httc_malloc (sizeof (struct boot_ref_item_user) * (*num)))){
		httc_util_pr_error ("No mem for ref update data!\n");
		httc_free (ref_item_data);
		return TCF_ERR_NOMEM;
	}
	for (i = 0; i < *num; i++){
		if (ref_item_opt + sizeof (struct boot_ref_item) >= length){
			httc_util_pr_error ("Invalid ref_item_data\n");
			tcf_free_boot_measure_references (ref_user, i);
			httc_free (ref_item_data);
			return TCF_ERR_PARAMETER;
		}
		ref_item = (struct boot_ref_item *)((void*)ref_item_data + ref_item_opt);
		hash_total_length = ntohs (ref_item->be_hash_length) * ntohs (ref_item->be_hash_number);
		name_length = ntohs (ref_item->be_name_length);
		extend_size = ntohs (ref_item->be_extend_size);
		item_size = HTTC_ALIGN_SIZE (sizeof (struct boot_ref_item) + hash_total_length
					+ name_length + ntohs (ref_item->be_extend_size), 4);
		if (ref_item_opt + item_size > length){
			httc_util_pr_error ("Invalid ref_item_data\n");
			tcf_free_boot_measure_references (ref_user, i);
			httc_free (ref_item_data);
			return TCF_ERR_PARAMETER;
		}
		if (NULL == (buf = httc_malloc (hash_total_length + name_length + extend_size))){
			httc_util_pr_error ("No mem for ref user!\n");
			tcf_free_boot_measure_references (ref_user, i);
			httc_free (ref_item_data);
			return TCF_ERR_NOMEM;
		}
		ref_user[i].hash_length = ntohs (ref_item->be_hash_length);
		ref_user[i].hash_number = ntohs (ref_item->be_hash_number);
		ref_user[i].stage = ntohs (ref_item->be_stage);
		ref_user[i].is_control = (ntohs (ref_item->be_flags) & (1 << BOOT_REFERENCE_FLAG_CONTROL)) ? 1 : 0; 
		ref_user[i].is_enable = (ntohs (ref_item->be_flags) & (1 << BOOT_REFERENCE_FLAG_ENABLE)) ? 1: 0;
		ref_user[i].extend_size = extend_size;
		ref_user[i].hash = buf;
		ref_user[i].extend_buffer = buf + hash_total_length;
		ref_user[i].name = buf + hash_total_length + ref_user[i].extend_size;
		memcpy (ref_user[i].hash, ref_item->data, hash_total_length);
		memcpy (ref_user[i].extend_buffer, ref_item->data + hash_total_length, ref_user[i].extend_size);
		memcpy (ref_user[i].name, ref_item->data + hash_total_length + ref_user[i].extend_size, name_length);
		ref_item_opt += item_size;
	}
	*references = ref_user;
	if (ref_item_data) httc_free (ref_item_data);
	return TCF_SUCCESS;
}//proc 导出

/*
 * 	释放启动基准库内存。
 */
void tcf_free_boot_measure_references (struct boot_ref_item_user *references, int num)
{
	if (references){
		while (num --) {
			if (references[num].hash) httc_free (references[num].hash);
		}
		httc_free (references);
	}
}


/*
 * 	获取启动度量记录（采集值）
 */
int tcf_get_boot_measure_records(struct  boot_measure_record_user **boot_records,int *num)
{
	int i;
	int ret;
	int length = 0;
	int name_length = 0;
	int item_size = 0;
	int record_item_opt = 0;
	struct boot_measure_record *record_item = NULL;
	struct boot_measure_record *record_item_data = NULL;
	struct boot_measure_record_user *record_user = NULL;

	if (0 != (ret = tcs_get_boot_measure_records (&record_item_data, num, &length))){
		httc_util_pr_error ("tcs_get_boot_measure_references error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	if (NULL == (record_user = httc_calloc (*num, sizeof (struct boot_measure_record_user)))){
		httc_util_pr_error ("No mem for ref update data!\n");
		httc_free (record_item_data);
		return TCF_ERR_NOMEM;
	}
	for (i = 0; i < *num; i++){
		if (record_item_opt + sizeof (struct boot_measure_record) >= length){
			httc_util_pr_error ("Invalid bmeasure_record_item\n");
			tcf_free_boot_measure_records (record_user, i);
			httc_free (record_item_data);
			return TCF_ERR_PARAMETER;
		}
		record_item = (struct boot_measure_record *)((void*)record_item_data + record_item_opt);
		item_size = HTTC_ALIGN_SIZE (sizeof (struct boot_measure_record)
					+ ntohs (record_item->be_hash_length) + ntohs (record_item->be_name_length), 4);
		if (record_item_opt + item_size > length){
			httc_util_pr_error ("Invalid bmeasure_record_item\n");
			tcf_free_boot_measure_records (record_user, i);
			httc_free (record_item_data);
			return TCF_ERR_PARAMETER;
		}
		
		record_user[i].hash_length = ntohs (record_item->be_hash_length);
		record_user[i].stage = ntohs (record_item->be_stage);
		record_user[i].result = ntohl (record_item->be_result);
		record_user[i].measure_time = ntohll (record_item->be_measure_time);
		memcpy (record_user[i].hash, record_item->data, ntohs (record_item->be_hash_length));
		name_length = ntohs (record_item->be_name_length);
		if (NULL == (record_user[i].name = httc_malloc (name_length))){
			httc_util_pr_error ("No mem for record name!\n");
			tcf_free_boot_measure_records (record_user, i);
			httc_free (record_item_data);
			return TCF_ERR_NOMEM;
		}
		memcpy (record_user[i].name, record_item->data + ntohs (record_item->be_hash_length), name_length);
		record_item_opt += item_size;
	}
	*boot_records = record_user;

	if (record_item_data) httc_free (record_item_data);
	return TCF_SUCCESS;
}

/*
 * 	释放启动记录内存。
 */
void tcf_free_boot_measure_records(struct  boot_measure_record_user *boot_records, int num)
{
	if (boot_records){
		while (num --) {
			if (boot_records[num].name) httc_free (boot_records[num].name);
		}
		httc_free (boot_records);
	}
}

/*
 * 	启动度量
 */
int tcf_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen){

		return tcs_boot_measure (stage, num, block, objAddr, objLen);
}

/*
 *	简易启动度量
 */
int tcf_simple_boot_measure (uint32_t stage, uint8_t* digest, uint8_t *obj, uint32_t objLen){
		return tcs_simple_boot_measure ( stage, digest,  obj, objLen);
}


