#include <linux/module.h>
#include "engine/ac_engine.h"
#include "tpcm/tpcmif.h"
#include "policy/list_fac.h"
#include "policy/policy_fac_cache.h"
#include "policy/hash_whitelist_path.h"
#include "utils/debug.h"
#include "protection/mod_protect.h"

extern int httc_register_module(struct module *mod);

static int __init httc_accessctl_init(void)
{
	int ret = 0;

	accessctl_credential_count_init();


	ret = httc_protect_module_on(module_name(THIS_MODULE));
	if(ret != 0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]register protect module[%s] error!\n", __func__, module_name(THIS_MODULE));
	}

	list_fac_init();
	whitelist_path_init();

	ret = accessctl_engine_init();

	

	return ret;
}

static void __exit httc_accessctl_exit(void)
{
	accessctl_engine_exit();
	whitelist_path_exit();
	list_fac_exit();
	
	return;
}

module_init(httc_accessctl_init);
module_exit(httc_accessctl_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HTTCSEC");
