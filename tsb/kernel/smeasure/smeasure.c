#include <linux/module.h>
#include "engine/smeasure_engine.h"
#include "policy/hash_whitelist.h"
#include "policy/hash_critical_confile.h"
#include "policy/policy_whitelist_cache.h"
#include "msg/command.h"
#include "tpcm/tpcmif.h"
#include "policy/flush_dcache.h"

#include "protection/mod_protect.h"
#include "protection/process_protect.h"
#include "utils/debug.h"

static int __init httc_smeasure_init(void)
{
    int ret = 0;
	smeasure_credential_count_init();

	ret = init_flush_dcache_area();
	if (ret)
		goto out;

	ret = whitelist_init();
	if (ret < 0) {
		DEBUG_MSG(HTTC_TSB_INFO,"whitelist init error!\n");
		goto out;
	}

	/* whitelist policy cache init */
	ret = policy_whitelist_cache_init();
	if (ret < 0)
		goto whitelist_init_err_out;

	ret = load_whitelist();
	if (ret < 0)
		DEBUG_MSG(HTTC_TSB_INFO,"load_whitelist error!\n");

	ret = critical_confile_init();
	if (ret < 0) {
		DEBUG_MSG(HTTC_TSB_INFO,"critical_confile init error!\n");
		goto whitelist_cache_init_err_out;
	}

	ret = load_critical_confile();
	if (ret < 0)
		DEBUG_MSG(HTTC_TSB_INFO,"load_critical_confile error!\n");



	ret = httc_protect_module_on(module_name(THIS_MODULE));
	if(ret != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"[%s]register protect module[%s] error!\n",__func__, module_name(THIS_MODULE));
	}

        if((ret = httc_process_protect_init()))
        {
                DEBUG_MSG(HTTC_TSB_INFO,"process protect init failed! ret = %d\n", ret);
        }

	if (httcsec_io_command_register(COMMAND_ADD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_add_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_ADD_WHITELIST_POLICY);
		goto whitelist_cache_init_err_out;
	}
	if (httcsec_io_command_register(COMMAND_DELETE_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_del_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_DELETE_WHITELIST_POLICY);
		goto whitelist_cache_init_err_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_RELOAD_WHITELIST_POLICY);
		goto whitelist_cache_init_err_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_CRITICAL_CONFILE_POLICY, (httcsec_io_command_func)ioctl_critical_confile_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_RELOAD_CRITICAL_CONFILE_POLICY);
		goto whitelist_cache_init_err_out;
	}
	if (httcsec_io_command_register(COMMAND_WHITELIST_USER_INTERFACE, (httcsec_io_command_func)ioctl_whitelist_user_interface)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_WHITELIST_USER_INTERFACE);
	}

	

    ret = smeasure_engine_init();
    if (ret)
            goto smeasure;
    goto out;

smeasure:
    smeasure_engine_exit();
	httcsec_io_command_unregister(COMMAND_WHITELIST_USER_INTERFACE, (httcsec_io_command_func)ioctl_whitelist_user_interface);
	httcsec_io_command_unregister(COMMAND_RELOAD_CRITICAL_CONFILE_POLICY, (httcsec_io_command_func)ioctl_critical_confile_reload_policy);
	httcsec_io_command_unregister(COMMAND_RELOAD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_reload_policy);
	httcsec_io_command_unregister(COMMAND_DELETE_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_del_policy);
	httcsec_io_command_unregister(COMMAND_ADD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_add_policy);


	critical_confile_exit();
whitelist_cache_init_err_out:
	policy_whitelist_cache_exit();
whitelist_init_err_out:
	whitelist_exit();
out:
    return ret;
}

static void __exit httc_smeasure_exit(void)
{
	if(check_module_protect_status(module_name(THIS_MODULE)) == 0){
		return ;
	}else{
		smeasure_engine_exit();
		httc_process_protect_exit();

		httcsec_io_command_unregister(COMMAND_WHITELIST_USER_INTERFACE, (httcsec_io_command_func)ioctl_whitelist_user_interface);
		httcsec_io_command_unregister(COMMAND_RELOAD_CRITICAL_CONFILE_POLICY, (httcsec_io_command_func)ioctl_critical_confile_reload_policy);
		httcsec_io_command_unregister(COMMAND_RELOAD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_reload_policy);
		httcsec_io_command_unregister(COMMAND_DELETE_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_del_policy);
		httcsec_io_command_unregister(COMMAND_ADD_WHITELIST_POLICY, (httcsec_io_command_func)ioctl_whitelist_add_policy);

		

		critical_confile_exit();

		policy_whitelist_cache_exit();

		whitelist_exit();
		return;
	}
}

module_init(httc_smeasure_init);
module_exit(httc_smeasure_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HTTCSEC");
