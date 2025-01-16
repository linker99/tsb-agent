#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_kernel_policy.h"
#include "tcs_process_def.h"
#include "tcs_policy_def.h"
#include "tcs_dmeasure_def.h"
#include "tcs_protect_def.h"
#include "tcs_tnc_def.h"
#include "tcs_auth_def.h"
#include "tcs_policy_mgmt.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk get_kernel_policy test");


/*
 * 读取全部进程身份
 */
int tcsk_get_process_ids_test (void)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	int num = 0;
	int op = 0;
	int hash_len = 0;
	int length = 0;
	
	struct process_identity *ids = NULL;
	struct process_identity *cur = NULL;
	
	ret = tcsk_get_process_ids (&ids, &num, &length);
//	httc_util_dump_hex ("roles", roles , length);
	if(ret){
		printk("[Error] tcsk_get_process_ids ret:0x%08x\n",ret);
		return -1;
	}
	

	for(;i < num; i++){
		cur = (struct process_identity *)((uint8_t *)ids + op);
		printk("================RUN:%d================\n",i);
		printk ("ids[%d] name: %s\n",i, cur->data + (1 + ntohs(cur->be_lib_number)) * ntohs(cur->be_hash_length));
		printk ("ids[%d] specific_libs: %s\n",i, cur->specific_libs == 0 ? "USE" : "UNUSE");
		printk ("ids[%d] lib number: %d\n",i, (uint32_t)ntohs(cur->be_lib_number));
		hash_len = (int)ntohs(cur->be_hash_length);
		for(j = 0; j < ntohs(cur->be_lib_number) + 1;j++){
			printk("[%d-%d]\n",i,j);
			httc_util_dump_hex ("HASH IS", cur->data + (j * hash_len) , hash_len);
		}
		op += httc_align_size(hash_len * (1 + ntohs(cur->be_lib_number))  + cur->name_length + sizeof(struct process_identity), 4);		
	}
	printk("tcs_get_process_roles success!\n");
	if(ids) httc_vfree(ids);
	return 0;
}

/*
 * 读取全部进程角色
 */
int tcsk_get_process_roles_test (void)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	int num = 0;
	int length = 0;
	int pop = 0;
	int op = 0;
	int name_number = 0;
	unsigned char name[128];
	struct process_role *roles = NULL;
	struct process_role *pcur = NULL;
	struct role_member *cur = NULL;

	ret = tcsk_get_process_roles(&roles,&num,&length);
//	httc_util_dump_hex ("roles", roles , length);
	if(ret){
		printk("[Error] tcsk_get_process_roles ret:0x%08x\n",ret);
		return -1;
	}
	
	for(;i < num;i++){
		pcur = (struct process_role *)((uint8_t *)roles + pop);
		printk("================RUN:%d================\n",i);
		memset(name,0,128);
		op = ntohl(pcur->be_name_length);
		memcpy(name,pcur->members,op);
		printk("name:%s\n",name);
		name_number = ntohl(pcur->be_members_number);
		for(j = 0;j < name_number;j++){
			cur = (struct role_member *)(pcur->members + op);
			memset(name,0,128);
			memcpy(name,cur->name,cur->length);
			printk("%d:%s\n",j,name);
			op += cur->length + sizeof(struct role_member);
		}
		pop += httc_align_size(op + sizeof(struct process_role), 4);
		printk("\n\n");		 
	}
	printk("tcsk_get_process_roles success!\n");
	if(roles) httc_vfree(roles);
	return 0;
}


/*
 * 获取全局控制策略
 */
int tcsk_get_global_control_policy_test (void)
{
	int ret = 0;
	struct global_control_policy policy;
	ret = tcsk_get_global_control_policy (&policy);
	if(ret) {
		printk ("[tcsk_get_global_control_policy_test] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}
	
	printk ("policy->size: 0x%08X\n", ntohl (policy.be_size));
	printk ("policy->boot_measure_on: %s\n", ntohl (policy.be_boot_measure_on) == 0 ? "OFF" : "ON");
	printk ("policy->program_measure_on: %s\n", ntohl (policy.be_program_measure_on) == 0 ? "OFF" : "ON");
	printk ("policy->dynamic_measure_on: %s\n", ntohl (policy.be_dynamic_measure_on) == 0 ? "OFF" : "ON");
	printk ("policy->boot_control: %s\n", ntohl (policy.be_boot_control) == 0 ? "NOT" : "CONTROL");
	printk ("policy->program_control: %s\n", ntohl (policy.be_program_control) == 0 ? "NOT" : "CHECK");
	printk ("policy->be_tsb_flag1: %s\n", ntohl (policy.be_tsb_flag1) == 0 ? "NOT" : "CHECK");
	printk ("policy->be_tsb_flag2: %s\n", ntohl (policy.be_tsb_flag2) == 0 ? "NOT" : "CHECK");
	printk ("policy->be_tsb_flag3: %s\n", ntohl (policy.be_tsb_flag3) == 0 ? "NOT" : "CONTROL");
	printk ("policy->program_measure_mode: %d\n", ntohl (policy.be_program_measure_mode));
	printk ("policy->measure_use_cache: %s\n", ntohl (policy.be_measure_use_cache) == 0 ? "NOT" : "USE_CACHE");
	printk ("policy->dmeasure_max_busy_delay: %d\n", ntohl (policy.be_dmeasure_max_busy_delay));
	printk ("policy->process_dmeasure_ref_mode: %s\n", 
		ntohl (policy.be_process_dmeasure_ref_mode) == 0 ? "Collection at startup" : "File library integrity");
	printk ("policy->process_dmeasure_match_mode: %s\n", 
		ntohl (policy.be_process_dmeasure_match_mode) == 0 ? "Only hash" : "Band path");
	printk ("policy->program_measure_match_mode: %s\n",
		ntohl (policy.be_program_measure_match_mode) == 0 ? "Only hash" : "Band path");
	printk ("policy->process_dmeasure_lib_mode: %s\n", 
		ntohl (policy.be_process_dmeasure_lib_mode) == 1 ? "MEASURE" : "NOT");
	printk ("policy->process_verify_lib_mode: %d\n",ntohl (policy.be_process_verify_lib_mode) );
	printk ("policy->process_dmeasure_sub_process_mode: %s\n", 
		ntohl (policy.be_process_dmeasure_sub_process_mode) == 1 ? "MEASURE" : "NOT");
	printk ("policy->process_dmeasure_old_process_mode: %s\n", 
		ntohl (policy.be_process_dmeasure_old_process_mode) == 1 ? "MEASURE" : "NOT");
	printk ("policy->process_dmeasure_interval: %d\n", ntohl(policy.be_process_dmeasure_interval));
	
	
	return 0;
}


int tcsk_get_tnc_policy_test (void)
{

	int ret = 0;
	int i = 0;
	int num = 0;
	struct tnc_policy *policies = NULL;
	int length = 0;
	ret = tcsk_get_tnc_policy((struct tnc_policy **)&policies, &length);
	if(ret){
		printk ("[tcsk_get_tnc_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	printk("================tnc_policy================\n");
	printk ("policies->server_ip: 0x%08X\n", ntohl(policies->be_server_ip));
	printk ("policies->server_port: %d\n", ntohs (policies->be_server_port));
	printk ("policies->control_mode: %s\n", ntohl (policies->be_control_mode) == 0 ? "UNCONTROL" : "CONTROL ALL");
	printk ("policies->encrypt_auth: %s\n", policies->encrypt_auth == 0 ? "NO" : "YES");
	printk ("policies->server_testify: %s\n", policies->server_testify == 0 ? "NO" : "YES");
	printk ("policies->report_auth_fail: %s\n", policies->report_auth_fail == 0 ? "NO" : "YES");
	printk ("policies->report_session: %s\n", policies->report_session == 0 ? "NO" : "YES");
	printk ("policies->be_session_expire: %d\n", ntohl (policies->be_session_expire));
	printk ("policies->be_exception_number: %d\n", ntohl(policies->be_exception_number));
	num = ntohl(policies->be_exception_number);
	
	for(;i < num; i++){
		printk("================tnc_policy_item:%d================\n",i);
		printk ("protocol: %s\n", ntohl(policies->exceptions[i].be_protocol) == 0 ? "UDP" : "TCP");
		printk ("remote_ip: 0x%08X\n", ntohl(policies->exceptions[i].be_remote_ip));
		printk ("local_ip: 0x%08X\n", ntohl(policies->exceptions[i].be_local_ip));		
		printk ("remote_port: %d\n", ntohs (policies->exceptions[i].be_remote_port));
		printk ("local_port: %d\n", ntohs (policies->exceptions[i].be_local_port));		
	}
	if(policies) httc_vfree(policies);	
	return 0;
}


/*
 * 	获取动态度量策略
 */
int tcsk_get_dmeasure_policy_test (void)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int size = 0;
	struct  dmeasure_policy_item *policy = NULL;
	ret = tcsk_get_dmeasure_policy (&policy, &num, &size);
	if (ret){
		printk ("[tcsk_get_dmeasure_policy_test] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		printk ("\n");
		printk ("item index: %d\n", i);
		printk ("[%d].be_type: %d\n", i, ntohl (policy[i].be_type));
		printk ("[%d].be_interval_milli: %d\n", i, ntohl(policy[i].be_interval_milli));
		printk ("[%d].object: %s\n", i, policy[i].object);
	}
	printk ("\n");
	
	if (policy)	httc_vfree (policy);
	return 0;
}

/*
 * 	获取进程动态度量策略
 */
int tcsk_get_dmeasure_process_policy_test (void)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int ops = 0;
	int size = 0;
	int item_size = 0;
	uint8_t *policy = NULL;
	struct dmeasure_process_item *item = NULL;
	ret = tcsk_get_dmeasure_process_policy ((struct dmeasure_process_item **)&policy, &num, &size);
	if (ret){
		printk ("[tcsk_get_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		if ((ops + sizeof (struct dmeasure_process_item)) >= size){
				printk ("Invalid item[%d] data!\n", i);
				ret = -1;
				goto out;
		}
		item = (struct dmeasure_process_item *)(policy + ops);
		item_size = httc_align_size (sizeof (struct  dmeasure_process_item) + ntohs(item->be_object_id_length), 4);
		if ((ops + item_size) > size){
				printk ("Invalid item[%d] data!\n", i);
				ret = -1;
				goto out;
		}

		printk ("\n");
		printk ("item index: %d\n", i);
        printk ("[%d].object_id_type: %d\n", i, item->object_id_type);
        printk ("[%d].sub_process_mode: %d\n", i, item->sub_process_mode);
        printk ("[%d].old_process_mode: %d\n", i, item->old_process_mode);
        printk ("[%d].share_lib_mode: %d\n", i, item->share_lib_mode);
        printk ("[%d].measure_interval: %d\n", i, ntohl(item->be_measure_interval));
        printk ("[%d].object_id_length :%d\n", i, ntohs(item->be_object_id_length));
		if (item->object_id_type == PROCESS_DMEASURE_OBJECT_ID_HASH){
			printk ("[%d].", i); httc_util_dump_hex ("object_id", item->object_id, ntohs(item->be_object_id_length));
		}else
			printk ("[%d].object_id: %s\n", i, item->object_id);
		ops += item_size;
	}
	printk ("\n");

out:
	if (policy)	httc_vfree (policy);
	return ret;
}

/*
 * 获取进程跟踪保护策略
 */	
int tcsk_get_ptrace_protect_policy_test (void)
{
	int ret = 0;
	int i = 0;
	int ops = 0;
	int size = 0;
	struct ptrace_protect *policy = NULL;
	
	ret = tcsk_get_ptrace_protect_policy ((struct ptrace_protect **)&policy, &size);
	if (ret){
		printk ("[tcsk_get_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	if (policy){
		printk ("PTRACE PROTECT:\n");
		printk ("  total_length: %d\n", ntohl(policy->be_total_length));
		printk ("  ptrace_protect: %d\n", ntohl(policy->be_ptrace_protect));
		printk ("  ptracer_number: %d\n", ntohl(policy->be_ptracer_number));
		printk ("  non_tracee_number: %d\n", ntohl(policy->be_non_tracee_number));

		printk ("    ptracer process:\n");
		for (i = 0; i < ntohl(policy->be_ptracer_number); i++){
			ops += sizeof (struct process_name);
			printk ("    [%d] %s\n", i, policy->process_names + ops);
			ops += httc_align_size (strlen (policy->process_names + ops) + 1, 4);
		}
		printk ("    non tracee process:\n");
		for (i = 0; i < ntohl(policy->be_non_tracee_number); i++){
			ops += sizeof (struct process_name);
			printk ("    [%d] %s\n", i, policy->process_names + ops);
			ops += httc_align_size (strlen (policy->process_names + ops) + 1, 4);
		}
		printk ("\n");

		httc_vfree (policy);
	}

	return 0;
}

/*
 * 获取TPCM管理策略
 */	

void show_admin_auth_policy(struct admin_auth_policy *policies, int num){	
	
	
}

int tcs_util_get_admin_auth_policies_test(void){

	int i = 0;
	int ret = 0;
	int num = 0;
	struct admin_auth_policy *list = NULL;

	ret = tcs_util_get_admin_auth_policies(&list,&num);
		if(ret){
			printk("[Error] tcs_util_get_admin_auth_policies_test ret:0x%08X\n",ret);
			ret = -1;
		}

	for(;i < num; i++){
		printk("================admin_auth_policy:%d================\n",i);
		printk ("policies->be_object_id: 0x%08X\n", ntohl ((list + i)->be_object_id));
		printk ("policies->be_admin_auth_type: 0x%08X\n", ntohl ((list + i)->be_admin_auth_type));
		printk ("policies->be_policy_flags: 0x%08X\n", ntohl ((list + i)->be_policy_flags));
		printk ("policies->be_user_or_group: 0x%08X\n", ntohl ((list + i)->be_user_or_group));
		printk ("policies->process_or_role: %s\n", (list + i)->process_or_role);		
	}
	
	if(list) httc_vfree(list);
	return ret;
}

int get_kernel_policy_init(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
	tcsk_get_tnc_policy_test();
	tcsk_get_process_ids_test ();
	tcsk_get_process_roles_test ();
	tcsk_get_global_control_policy_test ();
	tcsk_get_dmeasure_policy_test ();
	tcsk_get_dmeasure_process_policy_test ();
	tcsk_get_ptrace_protect_policy_test ();
	tcs_util_get_admin_auth_policies_test();
	return 0;
}

void get_kernel_policy_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init (get_kernel_policy_init);
module_exit (get_kernel_policy_exit);

