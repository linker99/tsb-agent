#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/module.h>

#include "memdebug.h"
#include "debug.h"
#include "tcs_error.h"
#include "tcs_policy_mgmt.h"

#include "tcs_auth.h"
#include "tcs_policy.h"
#include "tcs_process.h"
#include "tcs_dmeasure.h"
#include "tcs_kernel_policy.h"

int tcsk_get_process_ids (struct process_identity **ids, int *num, int *length)
{ 
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*num = gst_policy_mgmt->process_id_num;
	*length = gst_policy_mgmt->process_id_size;
	if(*length){
		if (NULL == (*ids = httc_vmalloc (*length))){
			httc_util_pr_error ("ids memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*ids, gst_policy_mgmt->process_ids, *length);
	}	
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_process_ids);

int tcsk_get_process_roles (struct process_role **roles, int *num, int *length)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*num = gst_policy_mgmt->process_role_num;
	*length = gst_policy_mgmt->process_role_size;
	if(*length){
		if (NULL == (*roles = httc_vmalloc (*length))){
			httc_util_pr_error ("roles memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*roles, gst_policy_mgmt->process_roles, *length);
	}
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_process_roles);

int tcsk_get_global_control_policy (struct global_control_policy *policy)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	if (!gst_policy_mgmt->global_ctrl_policy){
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_ITEM_NOT_FOUND;
	}
	if (policy)	memcpy (policy, gst_policy_mgmt->global_ctrl_policy, sizeof (struct global_control_policy));
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_global_control_policy);

int tcsk_get_dmeasure_policy(struct dmeasure_policy_item **policy, int *item_count, int *length)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*item_count = gst_policy_mgmt->dmeasure_policy_num;
	*length = gst_policy_mgmt->dmeasure_policy_size;
	if(*length){
		if (NULL == (*policy = httc_vmalloc (*length))){
			httc_util_pr_error ("policy memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*policy, gst_policy_mgmt->dmeasure_policy_list, *length);
	}	
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_dmeasure_policy);

int tcsk_get_dmeasure_process_policy(struct dmeasure_process_item **policy, int *item_count, int *length)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*item_count = gst_policy_mgmt->dmeasure_process_policy_num;
	*length = gst_policy_mgmt->dmeasure_process_policy_size;
	if(*length){
		if (NULL == (*policy = httc_vmalloc (*length))){
			httc_util_pr_error ("policy memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*policy, gst_policy_mgmt->dmeasure_process_policy_list, *length);
	}	
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_dmeasure_process_policy);

int tcsk_get_ptrace_protect_policy(struct ptrace_protect **policy, int *length)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*length = gst_policy_mgmt->ptrace_protect_policy_size;
	if(*length){
		if (NULL == (*policy = httc_vmalloc (*length))){
			httc_util_pr_error ("policy memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*policy, gst_policy_mgmt->ptrace_protect_policy, *length);
	}	
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_ptrace_protect_policy);

int tcsk_get_tnc_policy(struct tnc_policy **policy, int *length)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	mutex_lock (&gst_policy_mgmt->mutex);
	*length = gst_policy_mgmt->tnc_policy_size;
	if(*length){
		if (NULL == (*policy = httc_vmalloc (*length))){
			httc_util_pr_error ("policy memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*policy, gst_policy_mgmt->tnc_policy, *length);
	}	
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL_GPL (tcsk_get_tnc_policy);



