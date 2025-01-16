#include <linux/module.h>
#include <linux/sched.h>
#include "section/section.h"
#include "syscall/syscall.h"
#include "modules/modules.h"
#include "idt/idt.h"
#include "task/task.h"
#include "filesystem/filesystem.h"
#include "net/net.h"
#include "process_identity/process_identity.h"
#include "dmeasure/dmeasure.h"
#include "policy/policy_dmeasure.h"
#include "tpcm/tpcmif.h"
#include "protection/mod_protect.h"
#include "utils/traceability.h"
#include "utils/debug.h"

atomic_t dmeasure_hook_use;
int idt_flag;
int filesystem_flag;
int modules_flag;
int task_flag;
int section_flag;
int syscall_flag;
int net_flag;


extern int httc_register_module(struct module *mod);

static int dmeasure_all_modules_init(void)
{
	int ret = 0;
	struct dmeasure_feature_conf *dmeasure_feature = NULL;

	dmeasure_credential_count_init();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	utils_init();
#endif

#if defined(__x86_64__)
	ret = idt_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- idt dmeasure init success!\n");
		idt_flag = 1;
	}
#endif


	ret = net_init();
	if (ret == 0) 
	{
		DEBUG_MSG(HTTC_TSB_DEBUG,"------------------------- net dmeasure init success!\n");
		net_flag = 1;
	}

	ret = filesystem_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- filesystem dmeasure init success!\n");
		filesystem_flag = 1;
	}


	ret = modules_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- modules dmeasure init success!\n");
		modules_flag = 1;
	}
#if 1
	ret = task_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- task dmeasure init success!\n");
		task_flag = 1;
	}
#endif
	ret = section_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- kernel section dmeasure init success!\n");
		section_flag = 1;
	}

	ret = httc_syscall_init();
	if (ret == 0) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "------------------------- syscall dmeasure init success!\n");
		syscall_flag = 1;
	}

	dmeasure_feature = get_dmeasure_feature_conf();
	if(dmeasure_feature->measure_mode)
		set_measure_zone_to_tpcm(NULL, NULL, 0);

	ret = httc_protect_module_on(module_name(THIS_MODULE));
	if(ret != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]register protect module[%s] error!\n", __func__, module_name(THIS_MODULE));
	}

	return 0;
}

static void dmeasure_all_modules_exit(void)
{
#if defined(__x86_64__)
	if (idt_flag)
		idt_exit();
#endif

	if (net_flag)
		net_exit();
	if (filesystem_flag)
		filesystem_exit();

	if (modules_flag)
		modules_exit();
	if (task_flag)
		task_exit();
	if (section_flag)
		section_exit();
	if (syscall_flag)
		httc_syscall_exit();
	return;
}

static __init int httc_dmeasure_init(void)
{
	int ret = 0;

	ret = dmeasure_policy_init();
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO, "dmeasure_policy_init fail!\n");
		return ret;
	}

	ret = dmeasure_init();
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO, "dmeasure_init fail!\n");
		goto dmeasure_init_err_out;
	}

	ret = dmeasure_all_modules_init();
	if (ret)
		goto dmeasure_all_modules_init_err_out;

	ret = process_identity_init();
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "process_identity_init error!\n");


	goto out;

	process_identity_exit();
	dmeasure_all_modules_exit();
dmeasure_all_modules_init_err_out:
	dmeasure_exit();
dmeasure_init_err_out:
	dmeasure_policy_exit();

out:
	return ret;
}

static void __exit httc_dmeasure_exit(void)
{
	process_identity_exit();
	dmeasure_all_modules_exit();
	dmeasure_exit();
	//dmeasure_policy_exit();

	do {
		while (atomic_read(&dmeasure_hook_use) > 0) {
			DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure hook in use, we will wait\n");
			schedule_timeout_uninterruptible(HZ / 10);
		}
		schedule_timeout_uninterruptible(HZ / 10);
	} while (atomic_read(&dmeasure_hook_use) > 0);
	dmeasure_policy_exit();

	return;
}

module_init(httc_dmeasure_init);
module_exit(httc_dmeasure_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HTTCSEC");
