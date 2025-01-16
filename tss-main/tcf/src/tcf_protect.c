#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_protect.h"
#include "tcfapi/tcf_protect.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_error.h"
#include "tutils.h"
#include "tcsapi/tcs_notice.h"


/** 准备更新进程跟踪防护策略 */
int tcf_prepare_ptrace_protect_policy(
		struct ptrace_protect_user *items,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct ptrace_protect_update **update,int *olen)
{
	int i = 0;
	int ret = 0;
	int ops = 0;
	int item_max_len = 0;
	int name_length = 0;
	struct process_name *proc_names = NULL;
	struct ptrace_protect *item = NULL;
	struct ptrace_protect_update *policy_update = NULL;

	if (!tpcm_id || !olen)	return TCF_ERR_PARAMETER;
	if (tpcm_id_length > MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("tpcm_id_length is too long (%d > %d)\n", tpcm_id_length, MAX_TPCM_ID_SIZE);
		return TCF_ERR_INPUT_EXCEED;
	}

	if (items){
		item_max_len = sizeof (struct ptrace_protect_update)
			+ MAX_NAME_LENGTH * (items->ptracer_number + items->non_tracee_number);
	}else{
		item_max_len = sizeof (struct ptrace_protect_update);
	}
	if (NULL == (policy_update = httc_malloc (item_max_len))){
		httc_util_pr_error ("No mem for policy update data!\n");
		return TCF_ERR_NOMEM;
	}
	memset (policy_update, 0, item_max_len);

	if (items){
		item = &policy_update->data[0];
		item->be_ptrace_protect = htonl (items->is_ptrace_protect);
		item->be_ptracer_number = htonl (items->ptracer_number);
		item->be_non_tracee_number = htonl (items->non_tracee_number);
		for (i = 0; i < items->ptracer_number; i++){
			proc_names = (struct process_name *)(item->process_names + ops);
			if (!items->ptracer_names[i]){
				httc_free (policy_update);
				httc_util_pr_error ("items->ptracer_names[%d] is null\n", i);
				return TCF_ERR_BAD_DATA;
			}
			name_length = strlen (items->ptracer_names[i]) + 1;
			if ((ops + sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4))
				> (item_max_len - sizeof (struct ptrace_protect_update)))
			{
				httc_util_pr_error ("No space for ptracer_names\n");
				httc_free (policy_update);
				return TCF_ERR_NOMEM;
			}
			memcpy (proc_names->prcess_names, items->ptracer_names[i], name_length);
			proc_names->be_name_length = htonl (name_length);
			ops += sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4);
		}
		for (i = 0; i < items->non_tracee_number; i++){
			proc_names = (struct process_name *)(item->process_names + ops);
			if (!items->non_tracee_names[i]){
				httc_free (policy_update);
				httc_util_pr_error ("items->non_tracee_names[%d] is null\n", i);
				return TCF_ERR_BAD_DATA;
			}
			name_length = strlen (items->non_tracee_names[i]) + 1;
			if ((ops + sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4))
				> (item_max_len - sizeof (struct ptrace_protect_update)))
			{
				httc_util_pr_error ("No space for non_tracee_names\n");
				httc_free (policy_update);
				return TCF_ERR_NOMEM;
			}
			memcpy (proc_names->prcess_names, items->non_tracee_names[i], name_length);
			proc_names->be_name_length = htonl (name_length);
			ops += sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4);
		}
		item->be_total_length = htonl (ops);
	}

	policy_update->be_size = htonl (sizeof (struct ptrace_protect_update));
	policy_update->be_action = htonl (action);
	policy_update->be_replay_counter = htonll(replay_counter);
	policy_update->be_data_length = htonl (sizeof (struct ptrace_protect) + ops);
	memcpy (policy_update->tpcm_id, tpcm_id, tpcm_id_length);
	*update = policy_update;
	*olen = sizeof (struct ptrace_protect_update) + ops;
	return ret;
}

/** 更新进程跟踪防护策略 */
int tcf_update_ptrace_protect_policy(struct ptrace_protect_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth)
{
	int ret;
	if (0 != (ret = tcs_update_ptrace_protect_policy (update, uid, cert_type, auth_length, auth))){
		httc_util_pr_error ("tcs_update_ptrace_protect_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	if (0 != (ret = tsb_set_ptrace_process_policy ((const char *)update->data, ntohl (update->be_data_length)))){
		if(ret == -1){
			httc_util_pr_info ("tsb_set_ptrace_process_policy : %d(0x%x)\n", ret, ret);
			}
		ret = TCF_SUCCESS;
	}
	httc_write_version_notices (ntohll (update->be_replay_counter), POLICY_TYPE_PTRACE_PROTECT);
	return TCF_SUCCESS;
}

/*
 * 读取进程跟踪防护策略
 */
int tcf_get_ptrace_protect_policy(struct ptrace_protect_user **ptrace_protect)
{
	int i = 0;
	int ret = 0;
	int ops = 0;
	int length = 0;
	int name_length = 0;
	struct process_name* proc_name = NULL;
	uint32_t ptracer_number = 0;
	uint32_t non_tracee_number = 0;
	struct ptrace_protect *policy = NULL;
	struct ptrace_protect_user *policy_user = NULL;

	if (0 != (ret = tcs_get_ptrace_protect_policy (&policy, &length))){
		httc_util_pr_error ("tcs_get_ptrace_protect_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	if (policy){
			ptracer_number = ntohl (policy->be_ptracer_number);
			non_tracee_number = ntohl (policy->be_non_tracee_number);
			if (NULL == (policy_user = httc_malloc (sizeof (struct ptrace_protect_user)
								+ sizeof (char *) * (ptracer_number + non_tracee_number)))){
				httc_util_pr_error ("No mem for policy_user_item data!\n");
				ret = TCF_ERR_NOMEM;
				goto out;
			}

			policy_user->ptracer_names = (void*)policy_user + sizeof (struct ptrace_protect_user);
			policy_user->non_tracee_names = (void*)policy_user + sizeof (struct ptrace_protect_user) + sizeof (char*) * ptracer_number;
			policy_user->is_ptrace_protect = ntohl (policy->be_ptrace_protect);
			policy_user->ptracer_number = ntohl (policy->be_ptracer_number);
			policy_user->non_tracee_number = ntohl (policy->be_non_tracee_number);

			for (i = 0; i < ptracer_number; i++){
				if ((ops + sizeof (struct process_name) > length)){
					httc_util_pr_error ("Invalid ptrace process name\n");
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				proc_name = (struct process_name *)(policy->process_names + ops);
				name_length = ntohl (proc_name->be_name_length);
				if ((ops + sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4)) > length){
					httc_util_pr_error ("Invalid ptrace process name\n");
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				if (NULL == (policy_user->ptracer_names[i] = httc_malloc (name_length))){
					httc_util_pr_error ("No mem for ptracer_names[%d]\n", i);
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				strcpy (policy_user->ptracer_names[i], proc_name->prcess_names);
				ops += sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4);
			}

			for (i = 0; i < non_tracee_number; i++){
				if ((ops + sizeof (struct process_name) > length)){
					httc_util_pr_error ("Invalid ptrace process name\n");
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				proc_name = (struct process_name *)(policy->process_names + ops);
				name_length = ntohl (proc_name->be_name_length);
				if ((ops + sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4)) > length){
					httc_util_pr_error ("Invalid ptrace process name\n");
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				if (NULL == (policy_user->non_tracee_names[i] = httc_malloc (name_length))){
					httc_util_pr_error ("No mem for ptracer_names[%d]\n", i);
					tcf_free_ptrace_protect_policy (policy_user);
					goto out;
				}
				strcpy (policy_user->non_tracee_names[i], proc_name->prcess_names);
				ops += sizeof (struct process_name) + HTTC_ALIGN_SIZE (name_length, 4);
			}

			*ptrace_protect = policy_user;

	}

out:
	if (policy) httc_free (policy);
	return 0;
}

/*
 * 释放进程跟踪防护策略内存
 */
void tcf_free_ptrace_protect_policy(struct ptrace_protect_user *ptrace_protect)
{
	int i = 0;
	if (ptrace_protect){
		for (i = 0; i < ptrace_protect->ptracer_number; i++)
			if (ptrace_protect->ptracer_names[i]) httc_free (ptrace_protect->ptracer_names[i]);
		for (i = 0; i < ptrace_protect->non_tracee_number; i++)
			if ((ptrace_protect->non_tracee_names[i])) httc_free (ptrace_protect->non_tracee_names[i]);
		httc_free (ptrace_protect);
	}
}
