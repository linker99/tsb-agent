#include <linux/module.h>
#include <linux/sched.h>

//#include "policy/global_policy.h"
#include "policy/feature_configure.h"
#include "msg/miscdev.h"

#include "utils/debug.h"
#include "hook/hook.h"
//#include "module/modules.h"
//#include "utils/algutil.h"
//int log_init(void);
//void log_exit(void);
#include "log/log_impl.h"
#include "notify/notify.h"
#include "procfs/procfs.h"

//int syscall_init(void );
//int syscall_exit(void);
#include "hook/syscall.h"
#include "protection/mod_protect.h"
#include "accessctl/accessctl.h"

#include "utils/vfs.h"
#include "trust_score/trust_score.h"
extern atomic_t platform_refcnt;
static int __init platform_init(void)
{
	int rc = 0;

	//if((rc = global_policy_init()))
	//{
	//	goto policy_out;
	//}
	if((rc = tsb_notify_init()))
	{
		goto out;
	}

	if((rc = policy_linkage_init()))
	{
		goto policy_linkage_out;
	}

	if((rc = log_init()))
	{
		goto log_out;
	}

	if((rc = miscdev_init()))
	{
		goto message_out;
	}
	if((rc = httc_syscall_init()))
	{
		goto syscall_out;
	}

	if((rc = hook_init()))
	{
		goto hook_out;
	}


	if(( rc = httc_module_protect_init() ))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"protect init failed!\n");
	}

	rc = httc_protect_module_on(module_name(THIS_MODULE));
	if(rc != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"[%s]register protect module[%s] error!\n",__func__, module_name(THIS_MODULE));
	}

	fac_process_msg_init();

	proc_init ();
  find_ovl_inode_real();


if(( rc = trust_score_init() ))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"trust score failed!\n");
		goto hook_out;
	}
	
if(( rc = debug_log_init() ))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"trust score failed!\n");
		goto hook_out;
	}

    DEBUG_MSG(HTTC_TSB_DEBUG,"HTTCSEC Platform Init Success!\n");
        
	goto out;

hook_out:
	httc_syscall_exit();
syscall_out:
	miscdev_exit();
message_out:
	log_exit();
log_out:
	policy_linkage_exit();
//notify_out:
policy_linkage_out:
	tsb_notify_exit();
//	global_policy_exit();
//policy_out:
out:
	return rc;

}

static void platform_exit(void)
{
	hook_exit();
	httc_syscall_exit();
	miscdev_exit();
	policy_linkage_exit();
	//global_policy_exit();
	httc_module_protect_exit();

	do{
		while(atomic_read( &platform_refcnt ) > 0){
			DEBUG_MSG(HTTC_TSB_DEBUG, "platform hook in use,we will wait\n");
			schedule_timeout_uninterruptible(HZ/10);
		}
		schedule_timeout_uninterruptible(HZ/10);
	}while(atomic_read( &platform_refcnt ) > 0);

	log_exit();
	tsb_notify_exit();
	proc_exit();
	trust_score_exit();
	debug_log_exit();
	DEBUG_MSG(HTTC_TSB_DEBUG, "HTTCSEC Platform Exit\n");
}

MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("HTTCSEC");
MODULE_LICENSE("GPL");

module_init(platform_init);
module_exit(platform_exit);
