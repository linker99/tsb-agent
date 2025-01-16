#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "memdebug.h"
#include "kutils.h"
#include "tcs_kernel_policy.h"
#include "tcs_auth_def.h"
#include "tcs_policy_mgmt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk update_admin_auth_policies test");

static uint32_t user_or_group = 0;


static int update_admin_auth_policies(void){
	int ret = 0;
	int list_size = 0;
	struct admin_auth_policy *list = NULL;
//	printk ("[%s:%d]\n", __func__, __LINE__);
	ret =  tcs_util_get_admin_auth_policies ((struct admin_auth_policy **)&list, &list_size);
	if(ret){
		printk ("[%s:%d] tcs_util_get_admin_auth_policies error\n", __func__, __LINE__);
		return -1;
	}
//	printk ("[%s:%d] num:%d\n", __func__, __LINE__, list_size);
	if(list_size){
		user_or_group = list->be_user_or_group;
		list->be_user_or_group = 666666;
//		printk ("[%s:%d]\n", __func__, __LINE__);
		ret = tcs_util_set_admin_auth_policies (list, list_size);
		if(ret){
			printk ("[%s:%d] tcs_util_set_admin_auth_policies error\n", __func__, __LINE__);
			if(list) httc_vfree(list);
			return -1;
		}
	}
	if(list) httc_vfree(list);
	return 0;
}

static int recovery_admin_auth_policies(void){
	int ret = 0;
	int list_size = 0;
	struct admin_auth_policy *list = NULL;
	
	ret =  tcs_util_get_admin_auth_policies ((struct admin_auth_policy **)&list, &list_size);
	if(ret){
		printk ("[%s:%d] tcs_util_get_admin_auth_policies error\n", __func__, __LINE__);
		return -1;
	}
	if(list_size){list->be_user_or_group = user_or_group;
		ret = tcs_util_set_admin_auth_policies (list, list_size);
		if(ret){
			printk ("[%s:%d] tcs_util_set_admin_auth_policies error\n", __func__, __LINE__);
			if(list) httc_vfree(list);
			return -1;
		}
	}
	if(list) httc_vfree(list);
	return 0;
}


int update_auth_policy_init(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
	return update_admin_auth_policies();	
	
}

void update_auth_policy_exit(void)
{	
	int ret = 0;
	ret = recovery_admin_auth_policies();
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init (update_auth_policy_init);
module_exit (update_auth_policy_exit);



