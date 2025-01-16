#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#include <linux/uidgid.h>
#endif
#include "sm3.h"
#include "memdebug.h"
#include "debug.h"
#include "version.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_auth.h"
#include "tcs_policy.h"
#include "tcs_process.h"
#include "tcs_protect.h"
#include "tcs_dmeasure.h"
#include "tcs_policy_mgmt.h"
#include "tcs_tnc.h"
#include "tcs_attest_def.h"
#include "tcs_kernel_policy.h"

struct tcs_policy_management *gst_policy_mgmt = NULL;

static void tcs_util_policy_management_dump (struct tcs_policy_management *mgmt)
{
	if (mgmt != NULL){
		printk ("tcsk_policy_management:\n");
		printk ("  mgmt->global_ctrl_policy: 0x%lx\n", (unsigned long)(mgmt->global_ctrl_policy));


		
		printk ("  mgmt->admin_auth_policy_num: %d\n", mgmt->admin_auth_policy_num);

		printk ("  mgmt->admin_auth_policy_list: 0x%lx\n", (unsigned long)mgmt->admin_auth_policy_list);
		printk ("  mgmt->process_id_num: %d\n", mgmt->process_id_num);
		printk ("  mgmt->process_id_size: %d\n", mgmt->process_id_size);
		printk ("  mgmt->process_ids: 0x%lx\n", (unsigned long)mgmt->process_ids);
		printk ("  mgmt->process_id_num: %d\n", mgmt->process_role_num);
		printk ("  mgmt->process_role_size: %d\n", mgmt->process_role_size);
		printk ("  mgmt->process_roles: 0x%lx\n", (unsigned long)mgmt->process_roles);
		printk ("  mgmt->process_role_num: %d\n", mgmt->process_role_num);
		printk ("  mgmt->dmeasure_policy_size: %d\n", mgmt->dmeasure_policy_size);
		printk ("  mgmt->dmeasure_policy_list: 0x%lx\n", (unsigned long )mgmt->dmeasure_policy_list);
		printk ("  mgmt->dmeasure_process_policy_num: %d\n", mgmt->dmeasure_process_policy_num);
		printk ("  mgmt->dmeasure_process_policy_size: %d\n", mgmt->dmeasure_process_policy_size);
		printk ("  mgmt->dmeasure_process_policy_list: 0x%lx\n", (unsigned long)mgmt->dmeasure_process_policy_list);
		printk ("  mgmt->ptrace_protect_policy_size: %d\n", mgmt->ptrace_protect_policy_size);
		printk ("  mgmt->ptrace_protect_policy: 0x%lx\n", (unsigned long) mgmt->ptrace_protect_policy);
		printk ("  mgmt->tnc_policy_size: %d\n", mgmt->tnc_policy_size);
		printk ("  mgmt->tnc_policy: 0x%lx\n", (unsigned long )mgmt->tnc_policy);
		printk ("\n");
	}
}

static void tcs_util_policy_management_load (struct tcs_policy_management *mgmt)
{

	int ret = -1;

	if (mgmt){
		/**  Get global control policy */
		if (0 != (ret = tcs_get_global_control_policy (mgmt->global_ctrl_policy))){
			printk ("[%s:%d]Tcs get global control policy hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

		/** Get admin auth policies */
		if (0 != (ret = tcs_get_admin_auth_policies ((struct admin_auth_policy **)&mgmt->admin_auth_policy_list, &mgmt->admin_auth_policy_num))){
			printk ("[%s:%d]Tcs get admin auth policies hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

		/** Get process ids */
		if (0 != (ret = tcs_get_process_ids (&mgmt->process_ids, &mgmt->process_id_num, &mgmt->process_id_size))){
			printk ("[%s:%d]Tcs get process ids hter: %d(0x%x)\n",__func__,__LINE__,ret, ret);
		}

		/** Get process roles */
		if (0 != (ret = tcs_get_process_roles (&mgmt->process_roles, &mgmt->process_role_num, &mgmt->process_role_size))){
			printk ("[%s:%d]Tcs get process roles hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

		/** Get dmeasure policy */
		if (0 != (ret = tcs_get_dmeasure_policy (&mgmt->dmeasure_policy_list, &mgmt->dmeasure_policy_num, &mgmt->dmeasure_policy_size))){
			printk ("[%s:%d]Tcs get dmeasure policy hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

	    /** Get dmeasure process policy */
	    if (0 != (ret = tcs_get_dmeasure_process_policy (&mgmt->dmeasure_process_policy_list, &mgmt->dmeasure_process_policy_num, 
	                 &mgmt->dmeasure_process_policy_size))){
	        printk ("[%s:%d]Tcs get dmeasure process policy hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
	 	}
	 
		/** Get ptrace protect policy */
		if (0 != (ret = tcs_get_ptrace_protect_policy (&mgmt->ptrace_protect_policy, &mgmt->ptrace_protect_policy_size))){
			printk ("[%s:%d]Tcs get ptrace protect policy hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

		/** Get tnc policy */
		if (0 != (ret = tcs_get_tnc_policy (&mgmt->tnc_policy, &mgmt->tnc_policy_size))){
			printk ("[%s:%d]Tcs get tnc policy hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		}

		tcs_util_policy_management_dump (mgmt);
	}
}

static void tcs_util_policy_management_clear (struct tcs_policy_management *mgmt)
{
	if (mgmt){
		if (mgmt->admin_auth_policy_list)	httc_vfree (mgmt->admin_auth_policy_list);
		if (mgmt->process_ids)	httc_vfree (mgmt->process_ids);
		if (mgmt->process_roles)	httc_vfree (mgmt->process_roles);
		if (mgmt->dmeasure_policy_list)	httc_vfree (mgmt->dmeasure_policy_list);
		if (mgmt->dmeasure_process_policy_list)	httc_vfree (mgmt->dmeasure_process_policy_list);
		if (mgmt->ptrace_protect_policy)	httc_vfree (mgmt->ptrace_protect_policy);
		if (mgmt->tnc_policy)	httc_vfree (mgmt->tnc_policy);
		memset (&mgmt->admin_auth_policy_num, 0,
			sizeof (struct tcs_policy_management) - ((void*)&mgmt->admin_auth_policy_num - (void*)mgmt));
	}
}

#define TCF_EXPAND_VERSION ((POLICY_TYPE_CRITICAL_FILE_INTEGRITY - POLICY_TYPE_KEYTREE)\
			+ (POLICIES_TYPE_MAX - POLICY_TYPE_FILE_PROTECT))
int tcs_policy_set_default_policy (void)
{
	int r;
	int i = 0;
	int num;
	int size;
	struct policy_version *ver_r = NULL;
	struct policy_version ver[POLICIES_TYPE_MAX];
	struct ptrace_protect *protect = NULL; 

	if((r = tcs_util_read_policy(TCS_POLICY_PTRACE_PROTECT_PATH, (void **)&protect,  &size, &num))) {
		httc_util_pr_error ("tcs_util_read_policy[protect] hter: %d(0x%x)\n", r, r);
		return r;
	}
	
	if(!size && !num && !protect){
		protect = httc_vmalloc(sizeof(struct ptrace_protect));
		if(protect == NULL){
			httc_util_pr_error ("protect httc_kmalloc hter\n");
			return TSS_ERR_NOMEM;
		}
		protect->be_total_length = 0;
		protect->be_ptrace_protect = 0;
		protect->be_ptracer_number = 0;
		protect->be_non_tracee_number = 0;
		
		if ((r = tcs_util_write_policy (TCS_POLICY_PTRACE_PROTECT_PATH, (void*)protect, sizeof (struct ptrace_protect), 1))){
			httc_util_pr_error ("tcs_util_write_policy[protect] hter: %d(0x%x)\n", r, r);
			if(protect) httc_vfree(protect);
			return r;
		}
	}
	//httc_util_dump_hex("default protect : ", protect, sizeof (struct ptrace_protect));
	if(protect) httc_vfree(protect);

	if ((r = tcs_util_read_policy (TCS_POLICY_VERSION_PATH, (void**)&ver_r, &size, &num)))	return r;
	if (!size && !num){
		for (i = 0; i < POLICIES_TYPE_MAX; i++){
			if(i < POLICY_TYPE_KEYTREE ){
				ver[i].be_policy = htonl (i);
				ver[i].be_version = 0;
			}else if(i == POLICY_TYPE_CRITICAL_FILE_INTEGRITY){
				ver[i - (POLICY_TYPE_CRITICAL_FILE_INTEGRITY - POLICY_TYPE_KEYTREE)].be_policy = htonl (i);
				ver[i - (POLICY_TYPE_CRITICAL_FILE_INTEGRITY - POLICY_TYPE_KEYTREE)].be_version = 0;
				
			}else{
				continue; 
			}
		}
		if ((r = tcs_util_write_policy (TCS_POLICY_VERSION_PATH, (void*)ver, sizeof (ver), POLICIES_TYPE_MAX - TCF_EXPAND_VERSION))){
			httc_util_pr_error ("tcs_util_write_policy[policy version] hter: %d(0x%x)\n", r, r);
			return r;
		}
	}
	if (ver_r)	httc_vfree (ver_r);

	return TSS_SUCCESS;
}

int tcs_policy_management_init (void)
{
	int ret = TSS_SUCCESS;
	struct tcs_policy_management *mgmt = NULL;

	if (NULL == (mgmt = httc_vzalloc (sizeof (struct tcs_policy_management)))){
		httc_util_pr_error ("Tcs global ctrl policy memory alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	
	if (NULL == (mgmt->global_ctrl_policy = httc_vzalloc (sizeof (struct global_control_policy)))){
		httc_util_pr_error ("Tcs global ctrl policy memory alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}


	ret = tcs_policy_set_default_policy ();
	if (ret)
	{
		httc_util_pr_error ("Tcs set default policy hter when init!\n");
		goto out;
	}

	tcs_util_policy_management_load (mgmt);

	mutex_init(&mgmt->mutex);
	gst_policy_mgmt = mgmt;
out:
	if (ret)
	{
		if ( mgmt )
		{
			if (mgmt->global_ctrl_policy)
			{
				httc_vfree(mgmt->global_ctrl_policy);
			}
			httc_vfree(mgmt);
		}
	}
	return ret;
}

int tcs_policy_management_reload (void)
{
	int ret = TSS_SUCCESS;
	if (!gst_policy_mgmt){
		return tcs_policy_management_init ();
	}else{

		ret = tcs_policy_set_default_policy ();
		if (ret)
		{
			httc_util_pr_error ("Tcs set default policy hter when reload!\n");
			return ret;
		}
		mutex_lock (&gst_policy_mgmt->mutex);
		tcs_util_policy_management_clear (gst_policy_mgmt);
		tcs_util_policy_management_load (gst_policy_mgmt);
		mutex_unlock (&gst_policy_mgmt->mutex);
	}

	return ret;
}

int tcs_util_get_admin_auth_policies (struct admin_auth_policy **list, int *list_size)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	*list_size = gst_policy_mgmt->admin_auth_policy_num;
	if(*list_size){
		if (NULL == (*list = httc_vmalloc (*list_size * sizeof (struct admin_auth_policy)))){
			httc_util_pr_error ("ids memory alloc hter!\n");
			mutex_unlock (&gst_policy_mgmt->mutex);
			return TSS_ERR_NOMEM;
		}
		memcpy (*list, gst_policy_mgmt->admin_auth_policy_list, sizeof (struct admin_auth_policy) * (*list_size));
	}
	mutex_unlock (&gst_policy_mgmt->mutex);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL(tcs_util_get_admin_auth_policies);	

int tcs_util_set_admin_auth_policies (struct admin_auth_policy *list, int list_size)
{
	struct admin_auth_policy *policy = NULL;
	
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	if(list_size){
		if (NULL == (policy = httc_vmalloc (sizeof (struct admin_auth_policy) * list_size))){
			httc_util_pr_error ("list memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (policy, list, sizeof (struct admin_auth_policy) * list_size);
	}
	
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->admin_auth_policy_list){
		httc_vfree (gst_policy_mgmt->admin_auth_policy_list);
		gst_policy_mgmt->admin_auth_policy_list = NULL;
	}
	gst_policy_mgmt->admin_auth_policy_list = policy;
	gst_policy_mgmt->admin_auth_policy_num = list_size;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_dmeasure_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}
EXPORT_SYMBOL(tcs_util_set_admin_auth_policies);	

int tcs_util_set_process_ids (struct process_identity *ids, int num, int length)
{
	struct process_identity *new_ids = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_ids = httc_vmalloc (length))){
			httc_util_pr_error ("ids memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		
		memcpy (new_ids, ids, length);
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->process_ids){
		httc_vfree (gst_policy_mgmt->process_ids);
		gst_policy_mgmt->process_ids = NULL;
	}
	gst_policy_mgmt->process_ids = new_ids;
	gst_policy_mgmt->process_id_num = num;
	gst_policy_mgmt->process_id_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_process_ids success!\n", __func__, __LINE__);
	
	return TSS_SUCCESS;
}

int tcs_util_set_process_roles (struct process_role *roles, int num, int length)
{
	struct process_role *new_roles = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_roles = httc_vmalloc (length))){
			httc_util_pr_error ("roles memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (new_roles, roles, length);
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->process_roles){
		httc_vfree (gst_policy_mgmt->process_roles);
		gst_policy_mgmt->process_roles = NULL;
	}
	gst_policy_mgmt->process_roles = new_roles;
	gst_policy_mgmt->process_role_num = num;
	gst_policy_mgmt->process_role_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_process_roles success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}

int tcs_util_set_global_control_policy (struct global_control_policy *policy)
{
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	memcpy (gst_policy_mgmt->global_ctrl_policy, policy, sizeof (struct global_control_policy));
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_global_control_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}

int tcs_util_set_dmeasure_policy (struct dmeasure_policy_item *policy, int item_count, int length)
{
	struct dmeasure_policy_item *new_item = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_item = httc_vmalloc (sizeof (struct dmeasure_policy_item) * item_count))){
			httc_util_pr_error ("list memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (new_item, policy, (sizeof (struct dmeasure_policy_item) * item_count));
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->dmeasure_policy_list){
		httc_vfree (gst_policy_mgmt->dmeasure_policy_list);
		gst_policy_mgmt->dmeasure_policy_list = NULL;
	}
	gst_policy_mgmt->dmeasure_policy_list = new_item;
	gst_policy_mgmt->dmeasure_policy_num = item_count;
	gst_policy_mgmt->dmeasure_policy_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_dmeasure_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}

int tcs_util_set_dmeasure_process_policy (struct dmeasure_process_item *policy, int item_count, int length)
{
	struct dmeasure_process_item *new_item = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_item = httc_vmalloc (length))){
			httc_util_pr_error ("list memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (new_item, policy, length);
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->dmeasure_process_policy_list){
		httc_vfree (gst_policy_mgmt->dmeasure_process_policy_list);
		gst_policy_mgmt->dmeasure_process_policy_list = NULL;
	}
	gst_policy_mgmt->dmeasure_process_policy_list = new_item;
	gst_policy_mgmt->dmeasure_process_policy_num = item_count;
	gst_policy_mgmt->dmeasure_process_policy_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_dmeasure_process_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}

int tcs_util_set_ptrace_protect_policy (struct ptrace_protect *policy, int length)
{
	struct ptrace_protect *new_item = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_item = httc_vmalloc (length))){
			httc_util_pr_error ("list memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (new_item, policy, length);
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->ptrace_protect_policy){
		httc_vfree (gst_policy_mgmt->ptrace_protect_policy);
		gst_policy_mgmt->ptrace_protect_policy = NULL;
	}
	gst_policy_mgmt->ptrace_protect_policy = new_item;
	gst_policy_mgmt->ptrace_protect_policy_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_dmeasure_process_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}

int tcs_util_set_tnc_policy (struct tnc_policy *policy, int length)
{
	struct tnc_policy *new_policy = NULL;
	if (!gst_policy_mgmt){
		httc_util_pr_error ("gst_policy_mgmt is uninitialized!\n");
		return TSS_ERR_ITEM_NOT_FOUND;
	}
	if(length){
		if (NULL == (new_policy = httc_vmalloc (length))){
			httc_util_pr_error ("list memory alloc hter!\n");
			return TSS_ERR_NOMEM;
		}
		memcpy (new_policy, policy, length);
	}
	mutex_lock (&gst_policy_mgmt->mutex);
	if (gst_policy_mgmt->tnc_policy){
		httc_vfree (gst_policy_mgmt->tnc_policy);
		gst_policy_mgmt->tnc_policy = NULL;
	}
	gst_policy_mgmt->tnc_policy = new_policy;
	gst_policy_mgmt->tnc_policy_size = length;
	mutex_unlock (&gst_policy_mgmt->mutex);

	printk ("[%s:%d] tcs_util_set_tnc_policy success!\n", __func__, __LINE__);
	return TSS_SUCCESS;
}


int tcs_util_calc_policy_hash (uint32_t object_id, uint8_t *hash, int *hash_len)
{
	int i = 0;
	int ret = 0;
	int policy_index = -1;
	int policy_list_num = 0;
	struct admin_auth_policy *policy_list = NULL;
	sm3_context ctx;
#ifndef TSS_DEBUG
	int process_name_length = 0;
	uint8_t process_name[256] = {0};
	unsigned int uid_or_gid = 0;	
	uid_t uid;
	gid_t gid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	uid = __kuid_val(current_uid());
	gid = __kgid_val(current_gid());
#else
	uid = current_uid();
	gid = current_gid();
#endif
#endif

	*hash_len = 0;
	if (0 != (ret = tcs_util_get_admin_auth_policies (&policy_list, &policy_list_num))){
		printk ("[%s:%d]tcs_util_get_admin_auth_policies hter: %d(0x%x)\n", __func__,__LINE__,ret, ret);
		ret = TSS_SUCCESS;
		goto out;
	}
	for (i = 0; i < policy_list_num; i ++){
		if (object_id == ntohl (policy_list[i].be_object_id)){
			policy_index = i;
			break;
		}
	}
	
	//httc_util_pr_error("object_id %d\n\n",ntohl (policy_list[i].be_object_id));
	
	if (policy_index == -1){
		printk ("[%s:%d]admin auth policy item is not found\n",__func__,__LINE__);
		ret = TSS_SUCCESS;
		goto out;
	}
#ifndef TSS_DEBUG
	if (ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_IDENTITY){
		if (0 != (ret = tcs_util_get_process_identity (process_name, &process_name_length))){
			httc_util_pr_error ("tcs_util_get_process_identity hter: %d(0x%x)\n", ret, ret);
			ret = TSS_ERR_ADMIN_AUTH;
			goto out;
		}
	}else if (ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_ROLE){
		if (0 == (ret = tcs_util_is_role_member (policy_list[policy_index].process_or_role))){
			httc_util_pr_error ("tcs_util_is_role_member hter: %d(0x%x)\n", ret, ret);
			ret = TSS_ERR_ADMIN_AUTH;
			goto out;
		}
	}
	if (ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_ENV){
		if (0 != (ret = tcs_util_tsb_measure_env ())){
			httc_util_pr_error ("tcs_util_tsb_measure_env hter: %d(0x%x)\n", ret, ret);
			ret = TSS_ERR_ADMIN_AUTH;
			goto out;
		}
	}
#endif

	httc_sm3_init (&ctx);
	httc_sm3_update (&ctx, (const unsigned char *)&policy_list[policy_index].be_policy_flags, sizeof (policy_list[policy_index].be_policy_flags));
#ifndef TSS_DEBUG
	if(ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_USER_ID){
		uid_or_gid = htonl(uid);
		httc_sm3_update (&ctx, (const unsigned char *)&(uid_or_gid), sizeof(unsigned int));
	}else if(ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_GROUP_ID){
		uid_or_gid = htonl(gid);
		httc_sm3_update (&ctx, (const unsigned char *)&(uid_or_gid), sizeof(unsigned int));
	}
	
	if(ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_IDENTITY){
		httc_sm3_update (&ctx, (const unsigned char *)process_name , strlen((const char *)process_name));
	}else if (ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_ROLE){
		httc_sm3_update (&ctx, (const unsigned char *)&policy_list[policy_index].process_or_role , strlen((const char *)(policy_list[policy_index].process_or_role)));
	}
#else
	if(ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_USER_ID || ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_GROUP_ID){
		httc_sm3_update (&ctx, (const unsigned char *)&policy_list[policy_index].be_user_or_group, sizeof (unsigned int));
	}
	if ((ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_IDENTITY) || (ntohl (policy_list[i].be_policy_flags) & POLICY_FLAG_PROCESS_ROLE)){
		httc_sm3_update (&ctx, (const unsigned char *)&policy_list[policy_index].process_or_role , strlen((const char *)(policy_list[policy_index].process_or_role)));
	}
#endif

	httc_sm3_finish (&ctx, hash);
	*hash_len = DEFAULT_HASH_SIZE;

out:
	if (policy_list) httc_vfree (policy_list);
	return ret;
}


static DEFINE_MUTEX(tcs_policy_mutex);

int tcs_util_read_policy (const char* path, void **policy, int *size, int *num)
{
	struct file *fp = NULL;
	unsigned int fsize = 0;
	ssize_t rsize = 0;
	char *rbuf = NULL;

	mutex_lock (&tcs_policy_mutex);
	
    fp = filp_open (path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
			if (-PTR_ERR(fp) == ENOENT){
				*policy = NULL;
				*size = 0;
				*num = 0;
				mutex_unlock (&tcs_policy_mutex);
				return TSS_SUCCESS;
			}else{
	            httc_util_pr_error ("hter occured while opening file %s, exiting...\n", path);
				mutex_unlock (&tcs_policy_mutex);
				return TSS_ERR_FILE;
			}
    }
    fsize = tpcm_file_size (fp);
	if (!fsize){
		*policy = NULL;
		*size = 0;
		*num = 0;
		filp_close(fp, NULL);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_SUCCESS;
	}

	if (NULL == (rbuf = httc_kmalloc (fsize, GFP_KERNEL))){
		httc_util_pr_error ("Alloc policy hter!\n");
		filp_close(fp, NULL);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_NOMEM;
	}

	rsize = tpcm_kernel_read (fp, (char *)rbuf, fsize, &fp->f_pos);
	if (rsize != fsize){
		httc_util_pr_error ("Read %s hter(%lu bytes read)\n", path, (unsigned long)rsize);
		filp_close(fp, NULL);
		httc_kfree (rbuf);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_READ;
	}
	filp_close(fp, NULL);
	mutex_unlock (&tcs_policy_mutex);
	
	*size = *((int*)rbuf);
	*num = *((int*)(rbuf+sizeof(int)));
	if (*size != (rsize - sizeof (int) * 2)){
		httc_util_pr_dev ("Invalid policy!\n");
		httc_kfree (rbuf);
		return TSS_ERR_BAD_DATA;
	}
	if (NULL == (*policy = httc_vmalloc (*size))){
		httc_util_pr_error ("Policy Alloc hter!\n");
		httc_kfree (rbuf);
		return TSS_ERR_NOMEM;
	}
	memcpy (*policy, rbuf + sizeof (int) * 2, rsize - sizeof (int) * 2);
	httc_kfree (rbuf);
	return TSS_SUCCESS;
}

int tcs_util_write_policy (const char* path, void *policy, int size, int num)
{
	struct file *fp = NULL;

	mutex_lock (&tcs_policy_mutex);
	
	fp = filp_open (path, O_CREAT | O_WRONLY, 0644);	
	if (IS_ERR(fp))
	{
		httc_util_pr_error("	tpcm_kernel_write");
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_FILE;
	}
 
	/** Write size */
	if (sizeof(int) != tpcm_kernel_write (fp, (const char *)&size, sizeof(int), &fp->f_pos)){
		filp_close(fp, NULL);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_WRITE;
	}
	/** Write num */
	if (sizeof(int) != tpcm_kernel_write (fp, (const char *)&num, sizeof(int), &fp->f_pos)){
		filp_close(fp, NULL);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_WRITE;
	}
	/** Write policy */
	if (size != tpcm_kernel_write(fp, policy, size, &fp->f_pos)){
		filp_close(fp, NULL);
		mutex_unlock (&tcs_policy_mutex);
		return TSS_ERR_WRITE;
	}
	filp_close(fp, NULL);
	mutex_unlock (&tcs_policy_mutex);

	return TSS_SUCCESS;
}


