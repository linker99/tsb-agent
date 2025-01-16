#include <linux/kernel.h>
#include <linux/mutex.h>
#include "../utils/debug.h"
#include "../policy/feature_configure.h"
#include "mod_protect.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/kprobes.h>
#endif

#define HTTC_PROTECT_ON    0x01
#define HTTC_PROTECT_OFF   0x00

#define PROTECT_MODS_ON     0x00000001
#define PROTECT_PROCESS_ON  0x00000002
#define PROTECT_OFF         0x00000000

DEFINE_MUTEX(mutex);

struct module_node {
	char name[MODULE_NAME_LEN];
	int flag;
};

static struct module_node protect_modules[PROTECTION_MAX] = {
	{
	 .name = PLATFORM_MOD_NAME,
	 .flag = 0,
	},
	{
	 .name = SMEASURE_MOD_NAME,
	 .flag = 0,
	},
	{
	 .name = DMEASURE_MOD_NAME,
	 .flag = 0,
	},
	{
	 .name = FAC_MOD_NAME,
	 .flag = 0,
	},
	{
	 .name = NET_MOD_NAME,
	 .flag = 0,
	},
	{
	 .name = UDISK_MOD_NAME,
	 .flag = 0,
	},
};


//int sprint_symbol(char *buffer, unsigned long address);
//struct module *(*find_module_fun)(const char *modname)=NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
//int dmeasure_pre(struct kprobe *p, struct pt_regs *regs) 
//{ 
//	return 0;
//}

struct module *(*find_module_fun)(const char *modname)=NULL;
 static struct kprobe kp = 
 {
 	.symbol_name = "find_module",
 };



int register_find_module_fun_name(void)
{
	int ret = -1;
        unsigned long *sym_address;	
//kp.pre_handler = dmeasure_pre;
	ret = register_kprobe(&kp);
	if (ret < 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"register_kprobe failed, error:%d\n", ret);
		return ret;
        }
        
		DEBUG_MSG(HTTC_TSB_DEBUG,"find_module_fun addr: %p\n", kp.addr);
        sym_address = (void *)kp.addr;
        DEBUG_MSG(HTTC_TSB_DEBUG,"sym_address %px\n", (void *)sym_address);	
//find_module_fun = (void*)kp.addr;
find_module_fun = (void*)sym_address;
	
	return ret;
}
void  exit_find_module_fun_name(void)
{
	
	DEBUG_MSG(HTTC_TSB_DEBUG,"find_module_fun addr: %p\n", kp.addr);
	unregister_kprobe(&kp);
}



#endif


int httc_all_module_protect_on(int status);

void protection_feature_conf_notify_func(void)
{
	int ret;
	struct global_control_policy global_policy = { 0 };
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n", __func__, ret);
	}
	else
	{
		 httc_all_module_protect_on(global_policy.be_tsb_flag1);
	}
}

int httc_module_protect_init(void)
{
	struct module* (*find_module_fun)(const char* modname) = NULL;
	int ret;
	ret = register_feature_conf_notify(FEATURE_PROTECTION, protection_feature_conf_notify_func);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_feature_conf_notify error ret[%d]!\n", __func__, ret);
		return -1;
	}
//	printk("===========================httc module protect init===========\r\n");
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
//	printk("=====================02======httc module protect init===========\r\n");
		register_find_module_fun_name();
	#else
		find_module_fun = find_module;
	#endif

	return 0;
}

void httc_module_protect_exit(void)
{
	int ret;
	ret = unregister_feature_conf_notify(FEATURE_PROTECTION, protection_feature_conf_notify_func);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], unregister_feature_conf_notify error ret[%d]!\n", __func__, ret);
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		exit_find_module_fun_name();
	#endif
}

int httc_mod_refcnt_inc(const char *name)
{
	struct module *mod;
	/* int refcnt = 0; */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	mod = find_module_fun(name);
#else
	mod = find_module(name);
#endif
	if (!mod)
	{
		return -ENOENT;
	}

	if (!try_module_get(mod))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], protect module[%s] failed!\n", __func__, name);
		return -ENODEV;
	}

	return 0;
}

int httc_mod_refcnt_dec(const char *name)
{
	struct module *mod;
	/* int refcnt = 0; */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	mod = find_module_fun(name);
#else
	mod = find_module(name);
#endif

	if (!mod)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], find module[%s] failed!\n", __func__, name);
		return -ENOENT;
	}

	module_put(mod);

	return 0;
}

int httc_all_module_protect_on(int status)
{
	int count = 0;
	struct module_node *mod = NULL;
	int ret = 0;

	for (count = 0; count < PROTECTION_MAX; count++)
	{
		mod = &protect_modules[count];
		if ((status & PROTECT_MODS_ON) && (mod->flag == HTTC_PROTECT_OFF))
		{
			mutex_lock(&mutex);
			ret = httc_mod_refcnt_inc(mod->name);
			if(ret == 0)
			{
				mod->flag = HTTC_PROTECT_ON;
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], module[%s] prtection status[%d] global status[%d] on!\n", __func__, mod->name, mod->flag, status);
			}
			mutex_unlock(&mutex);
		}


		if (!(status & PROTECT_MODS_ON) && (mod->flag == HTTC_PROTECT_ON))
		{
			mutex_lock(&mutex);
			ret = httc_mod_refcnt_dec(mod->name);
			if(ret == 0)
			{
				mod->flag = HTTC_PROTECT_OFF;
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], module[%s] protection status[%d] global status[%d] off!\n", __func__, mod->name, mod->flag, status);
			}
			mutex_unlock(&mutex);
		}
	}

	return 0;
}

/*
return value
0 need protect;
1 no need;
*/
int check_module_protect_status(char *name)
{
	int ret = -1;
	int count = 0;
	struct module_node *mod = NULL;

	for ( count = 0; count < PROTECTION_MAX; count++ ){
		mod = &protect_modules[count];
		if( strcmp(mod->name, name) == 0 )
			break;
		else
			mod = NULL;

	}

	if(mod){
		if(mod->flag == HTTC_PROTECT_ON){
			ret = 0;
		}else if(mod->flag == HTTC_PROTECT_OFF){
			ret = 1;
		}
	}else{
		ret = 1;
	}

	return ret;

}

EXPORT_SYMBOL(check_module_protect_status);

int httc_protect_module_on(char *name) 
{
	struct global_control_policy global_policy = { 0 };
	uint32_t tpcm_feature = 0;
	int valid_license = 0;
	struct module_node *mod = NULL;
	int count = 0;
	int ret = 0;
	int status = 0;

	for ( count = 0; count < PROTECTION_MAX; count++ )
	{
		mod = &protect_modules[count];
		if( strcmp(mod->name, name) == 0 )
			break;
		else
			mod = NULL;
	}

	if( mod == NULL )
	{
		DEBUG_MSG( HTTC_TSB_INFO, "Enter:[%s], protect module[%s] not in protection list\n", __func__, name );
		return -1;
	}

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n", __func__, ret);
		return -1;
	}

	status = global_policy.be_tsb_flag1;
	if ((status & PROTECT_MODS_ON) && (mod->flag == HTTC_PROTECT_OFF))
	{
		mutex_lock(&mutex);
		ret = httc_mod_refcnt_inc(mod->name);
		if(ret == 0)
			mod->flag = HTTC_PROTECT_ON;
		mutex_unlock(&mutex);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], module[%s] protect status[%d] globle policy[%d] on!\n", __func__, name, mod->flag, status);
	return 0;
}

EXPORT_SYMBOL( httc_protect_module_on );
