#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_dmeasure.h"
#include "tcfapi/tcf_dmeasure.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_attest_def.h"
#include "tutils.h"


#define MAX_OBJECT_LENGTH	256
#define MAX_PROCESS_DMEASURE_POLICY_ITEM_SIZE HTTC_ALIGN_SIZE((sizeof (struct dmeasure_process_item) + MAX_OBJECT_LENGTH), 4)

/*
 * 	准备更新动态度量策略
 */
int tcf_prepare_update_dmeasure_policy(
		struct dmeasure_policy_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_policy_update **policy,int *olen)
{
	int i = 0;
	struct dmeasure_policy_item *item = NULL;
	struct dmeasure_policy_update *policy_update = NULL;

	if ((num && !items) || !tpcm_id || !olen)	return TCF_ERR_PARAMETER;

	if (tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id_length is too long (%d > %d)\n", tpcm_id_length, MAX_TPCM_ID_SIZE);
		return TCF_ERR_INPUT_EXCEED;
	}

	*olen = sizeof (struct dmeasure_policy_update) + sizeof (struct dmeasure_policy_item) * num;
	if (NULL == (policy_update = httc_malloc (*olen))){
		httc_util_pr_error ("No mem for dmeasure policy update data!\n");
		return TCF_ERR_NOMEM;
	}
	memset (policy_update, 0, *olen);

	item = (struct dmeasure_policy_item *)policy_update->data;
	for (i = 0; i < num; i++){
		if (!items[i].name)	return TCF_ERR_PARAMETER;
		if ((strlen (items[i].name) + 1) > TPCM_DMEASURE_OBJECT_SIZE){
			httc_util_pr_error ("dmeasure policy name is too long (%d > %d)\n", (int)(strlen (items[i].name) + 1), TPCM_DMEASURE_OBJECT_SIZE);
			httc_free (policy_update);
			return TCF_ERR_INPUT_EXCEED;
		}
		item[i].be_type = htonl (items->type);
		item[i].be_interval_milli = htonl (items[i].interval_milli);
		memcpy (item[i].object, items[i].name, strlen (items[i].name));
	}

	policy_update->be_size = htonl (sizeof (struct dmeasure_policy_update));
	policy_update->be_action = htonl (action);
	policy_update->be_replay_counter = htonll (replay_counter);
	policy_update->be_item_number = htonl (num);
	policy_update->be_data_length = htonl (sizeof (struct dmeasure_policy_item) * num);
	memcpy (policy_update->tpcm_id, tpcm_id, tpcm_id_length);

	*policy = policy_update;
	return 0;
}

/*
 * 	准备更新进程动态度量策略
 */
int tcf_prepare_update_dmeasure_process_policy(
		struct dmeasure_process_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_process_policy_update **policy,int *olen)
{
	int i = 0;
	int ops = 0;
	int item_size = 0;
	struct dmeasure_process_item *item = NULL;
	struct dmeasure_process_policy_update *policy_update = NULL;

	if ((num && !items) || !tpcm_id || !olen)	return TCF_ERR_PARAMETER;

	if (tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id_length is too long (%d > %d)\n", tpcm_id_length, MAX_TPCM_ID_SIZE);
		return TCF_ERR_PARAMETER;
	}

	if (NULL == (policy_update = httc_malloc (sizeof (struct dmeasure_process_policy_update) + MAX_PROCESS_DMEASURE_POLICY_ITEM_SIZE * num))){
		httc_util_pr_error ("No mem for policy update data!\n");
		return TCF_ERR_NOMEM;
	}
	memset (policy_update, 0, sizeof (struct dmeasure_process_policy_update) + MAX_PROCESS_DMEASURE_POLICY_ITEM_SIZE * num);

	for (i = 0; i < num; i++){
		item_size = HTTC_ALIGN_SIZE (sizeof (struct dmeasure_process_item) + items[i].object_id_length, 4);
		if (ops + item_size > MAX_PROCESS_DMEASURE_POLICY_ITEM_SIZE * num){
			httc_util_pr_error ("Invalid item data\n");
			httc_free (policy_update);
			return TCF_ERR_PARAMETER;
		}
		item = (struct dmeasure_process_item *)(policy_update->data + ops);
		item->object_id_type = items[i].object_id_type;
		item->sub_process_mode = items[i].sub_process_mode;
		item->old_process_mode = items[i].old_process_mode;
		item->share_lib_mode = items[i].share_lib_mode;
		item->be_measure_interval = htonl (items[i].measure_interval);
		item->be_object_id_length = htons (items[i].object_id_length);
		memcpy (item->object_id, items[i].object_id, items[i].object_id_length);
		ops += item_size;

	}
	policy_update->be_size = htonl (sizeof (struct dmeasure_process_policy_update));
	policy_update->be_action = htonl (action);
	policy_update->be_replay_counter = htonll (replay_counter);
	policy_update->be_item_number = htonl (num);
	policy_update->be_data_length = htonl (ops);
	memcpy (policy_update->tpcm_id, tpcm_id, tpcm_id_length);

	*olen = sizeof (struct dmeasure_process_policy_update) + ops;
	*policy = policy_update;
	return 0;
}

/*
 * 	更新动态度量策略
 * 	设置、增加、删除。
 */
int tcf_update_dmeasure_policy(struct dmeasure_policy_update *policy,
			const char *uid, int auth_type, int auth_length, unsigned char *auth)
{
	int ret;
	if (0 != (ret = tcs_update_dmeasure_policy (policy, uid, auth_type, auth_length, auth))){
		httc_util_pr_error ("tcs_update_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	if (0 != (ret = tsb_set_dmeasure_policy ((const char *)policy->data, ntohl (policy->be_data_length)))){
	//	if(ret == -1)
		{
			httc_util_pr_info ("tsb_set_dmeasure_policy : %d(0x%x)\n", ret, ret);
			}
		ret = TCF_SUCCESS;
	}
	httc_write_version_notices (ntohll (policy->be_replay_counter), POLICY_TYPE_DMEASURE);
	return TCF_SUCCESS;
}

/*
 * 	更新动态度量策略
 * 	设置、增加、删除。
 */

int tcf_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth)
{
	int ret;
	if (0 != (ret = tcs_update_dmeasure_process_policy (policy, uid, auth_type, auth_length, auth))){
		httc_util_pr_error ("tcs_update_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	switch (ntohl (policy->be_action)){
		case POLICY_ACTION_SET:
			if (0 != (ret = tsb_reload_process_dmeasure_policy())){
				if(ret == -1){
					httc_util_pr_info ("tsb_reload_process_dmeasure_policy : %d(0x%x)\n", ret, ret);
					}
				//return TCF_ERR_TSB;
			}
			break;
		case POLICY_ACTION_ADD:
			if (0 != (ret = tsb_add_process_dmeasure_policy((const char *)policy->data, ntohl (policy->be_data_length)))){
				if(ret == -1){
					httc_util_pr_info ("tsb_add_process_dmeasure_policy : %d(0x%x)\n", ret, ret);
					}
				//return TCF_ERR_TSB;
			}
			break;
		case POLICY_ACTION_DELETE:
			if (0 != (ret = tsb_remove_process_dmeasure_policy((const char *)policy->data, ntohl (policy->be_data_length)))){
				if(ret == -1){
					httc_util_pr_info ("tsb_add_process_dmeasure_policy : %d(0x%x)\n", ret, ret);
					}
				//return TCF_ERR_TSB;
			}
			break;
		case POLICY_ACTION_MODIFY:
			if (0 != (ret = tsb_reload_process_dmeasure_policy())){
				if(ret == -1){
					httc_util_pr_info ("tsb_reload_process_dmeasure_policy: %d(0x%x)\n", ret, ret);
					}
				//return TCF_ERR_TSB;
			}
			break;
	}
	httc_write_version_notices (ntohll (policy->be_replay_counter), POLICY_TYPE_PROCESS_DMEASURE);
	return TCF_SUCCESS;
}

/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_policy (struct dmeasure_policy_item_user **policy, int *item_count)
{
	int i;
	int ret;
	int length = 0;
	int name_length = 0;
	struct dmeasure_policy_item *policy_item = NULL;
	struct dmeasure_policy_item_user *policy_user_item = NULL;

	if (0 != (ret = tcs_get_dmeasure_policy (&policy_item, item_count, &length))){
		httc_util_pr_error ("tcs_get_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	if (NULL == (policy_user_item = httc_malloc (sizeof (struct dmeasure_policy_item_user) * (*item_count)))){
		httc_util_pr_error ("No mem for policy_user_item data!\n");
		ret = TCF_ERR_NOMEM;
		goto out;
	}

	for (i = 0; i < *item_count; i++){
		name_length = strlen ((const char *)policy_item[i].object) + 1;
		if (NULL == (policy_user_item[i].name = httc_malloc (name_length))){
			httc_util_pr_error ("No mem for policy name!\n");
			tcf_free_dmeasure_policy (policy_user_item, i);
			ret = TCF_ERR_NOMEM;
			goto out;
		}

		policy_user_item[i].type = ntohl (policy_item[i].be_type);
		policy_user_item[i].interval_milli = ntohl (policy_item[i].be_interval_milli);
		memcpy (policy_user_item[i].name, policy_item[i].object, name_length);
	}
	*policy = policy_user_item;

out:
	if (policy_item) httc_free (policy_item);
	return ret;
}//proc 导出


/*
 * 	获取动态度量策略内存
 */
void tcf_free_dmeasure_policy(struct dmeasure_policy_item_user *policy,int item_count)
{
	if (policy){
		while (item_count --){
			if (policy[item_count].name)	httc_free (policy[item_count].name);
		}
		httc_free (policy);
	}
}

/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_process_policy(struct dmeasure_process_item_user **policy,int *item_count)
{
	int i = 0;
	int ret = 0;
	int ops = 0;
	int length = 0;
	struct dmeasure_process_item *dp_policy = NULL;
	struct dmeasure_process_item *item = NULL;
	struct dmeasure_process_item_user *item_user = NULL;

	if (0 != (ret = tcs_get_dmeasure_process_policy (&dp_policy, item_count, &length))){
		httc_util_pr_error ("tcs_get_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	if (NULL == (item_user = httc_calloc (*item_count, sizeof (struct dmeasure_process_item_user)))){
		httc_util_pr_error ("No mem for item_user!\n");
		ret = TCF_ERR_NOMEM;
		goto out;
	}

	for (i = 0; i < *item_count; i++){
		if ((ops + sizeof (struct dmeasure_process_item)) >= length){
				httc_util_pr_error ("Invalid item[%d] data!\n", i);
				tcf_free_dmeasure_process_policy (item_user, i);
				ret = TCF_ERR_NOMEM;
				goto out;
		}
		item = (struct dmeasure_process_item *)((void*)dp_policy + ops);
		item_user[i].object_id_length = ntohs (item->be_object_id_length);
		if ((ops + sizeof (struct dmeasure_process_item) + item_user[i].object_id_length) > length){
				httc_util_pr_error ("Invalid item[%d] data!\n", i);
				tcf_free_dmeasure_process_policy (item_user, i);
				ret = TCF_ERR_NOMEM;
				goto out;
		}
		if (NULL == (item_user[i].object_id = httc_malloc (item_user[i].object_id_length))){
			httc_util_pr_error ("No mem for item_user[%d].object_id!\n", i);
			tcf_free_dmeasure_process_policy (item_user, i);
			ret = TCF_ERR_NOMEM;
			goto out;
		}
		item_user[i].object_id_type = item->object_id_type;
		item_user[i].sub_process_mode = item->sub_process_mode;
		item_user[i].old_process_mode  = item->old_process_mode;
		item_user[i].share_lib_mode = item->share_lib_mode;
		item_user[i].measure_interval = ntohl(item->be_measure_interval);
		memcpy (item_user[i].object_id, item->object_id, item_user[i].object_id_length);
		ops += HTTC_ALIGN_SIZE (sizeof (struct dmeasure_process_item) + item_user[i].object_id_length, 4);
	}

	*policy = item_user;
out:
	if (dp_policy) httc_free (dp_policy);
	return ret;
}

/*
 * 	释放进程动态度量策略内存
 */
void tcf_free_dmeasure_process_policy(struct dmeasure_process_item_user *policy,int item_count)
{
	if (policy){
		while (item_count --){
			if (policy[item_count].object_id)	httc_free (policy[item_count].object_id);
		}
		httc_free (policy);
	}
}

/*
 * 	准备动态度量更新
 */
int tcf_prepare_update_dmeasure_reference(
		struct dmeasure_reference_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_reference_update **reference,int *olen){
	return 0;
}
/*
 * 	设置动态度量基准值
 */
int tcf_update_dmeasure_reference(struct dmeasure_reference_update *reference){
	return 0;
}

/*
* 	设置动态度量基准值，带认证
 */
int tcf_update_dmeasure_reference_auth(struct dmeasure_reference_update *reference,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth){
	return 0;
}


/*
 * 	获取动态度量基准库
 */
int tcf_get_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count){
	return 0;
}//proc 导出

/*
 * 	释放动态度量基准值内存
 */
void tcf_free_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count){
	//return 0;
}//proc 导出

