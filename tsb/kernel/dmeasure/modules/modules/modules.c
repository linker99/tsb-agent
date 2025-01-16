#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/crc32.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/cred.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
#include <linux/sysfs.h>
#endif
#include "dmeasure_types.h"
#include "version.h"
#include "../../policy/policy_dmeasure.h"
//#include "policy/list_dmeasure_trigger.h"
#include "sec_domain.h"
#include "function_types.h"
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
#include "log/log.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "utils/debug.h"

#include <trace/events/module.h>

#define SECTION_TEXT			".text"
#define SECTION_DATA			".data"
#define SECTION_LINKONCE		".gnu.linkonce.this_module"

static unsigned long modules_addr = INVALID_DATA_FULL_FF;
module_param(modules_addr, ulong, 0644);
MODULE_PARM_DESC(modules_addr, "ulong modules address");

struct modules_policy *modules_p = NULL;

//#define ACTION_NAME "ModuleList"
#define CIRCLE_NAME	"Periodicity"
#define ACTION_NAME DM_ACTION_MODULELIST_NAME

static struct list_head *sys_modules;
static LIST_HEAD(module_list);
static volatile int dmodule_count;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
struct module_sect_attr {
	struct bin_attribute battr;
	unsigned long address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[];
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 133) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
struct module_sect_attr {
	struct bin_attribute battr;
	unsigned long address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[0];
};
#else
struct module_sect_attr {
	struct module_attribute mattr;
	char *name;
	unsigned long address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[0];
};
#endif

struct module_info {
	struct list_head list;
	struct module *mod;
	int status;
	u32 code_crc32;
	unsigned char sm3_hash[32];
	char name[MODULE_NAME_LEN];
	int len_base;
	char base[0];
};



static int kernel_args_addr_init(void)
{
	if (modules_addr == INVALID_DATA_FULL_FF || modules_addr == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [MODULES] Argument Error!\n");
		return -EINVAL;
	} else {
		sys_modules = (struct list_head *)modules_addr;
		DEBUG_MSG(HTTC_TSB_DEBUG, "modules_addr:[%0lx]!\n", modules_addr);
	}

	return 0;
}

static unsigned long cal_module_code_segment_size(struct module *mod)
{
	const char *sect_name = NULL;
	unsigned long sect_addr = 0;
	struct module_sect_attrs *sect_attrs = NULL;
	unsigned long text_size = 0, data_size = 0, link_once_size = 0;
	int code_segment_size = 0;
	int i = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	code_segment_size = mod->core_layout.text_size;
#else
	code_segment_size = mod->core_text_size;
#endif
	return code_segment_size;

	//printk("modules[%s], module_core_addr[%lu]\n", mod->name, (unsigned long)(mod->core_layout.base));

	sect_attrs = mod->sect_attrs;
	if (!sect_attrs) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "module name [%s], sect_attrs is NULL!\n", mod->name);
		goto out;
	}

	for (i = 0; i < (sect_attrs->nsections); i++) 
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
		struct module_sect_attr *sattr = NULL;
		sattr = &sect_attrs->attrs[i];
		sect_name = sattr->battr.attr.name ;
		sect_addr = sattr->address;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 133) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
		sect_name = sect_attrs->attrs[i].battr.attr.name;
		sect_addr = sect_attrs->attrs[i].address;
#else
		sect_name = sect_attrs->attrs[i].name;
		sect_addr = sect_attrs->attrs[i].address;
#endif

		if (strcmp(sect_name, SECTION_TEXT) == 0)
		{
			text_size = sect_addr;
		}
		else if (strcmp(sect_name, SECTION_DATA) == 0)
		{
			data_size = sect_addr;
		}
		else if (strcmp(sect_name, SECTION_LINKONCE) == 0)
		{
			link_once_size = sect_addr;
		}
	}

	if (text_size && data_size) 
	{
		code_segment_size = data_size - text_size;
	} 
	else if (!data_size && link_once_size && text_size) 
	{
		code_segment_size = link_once_size - text_size;
	} 
	else if (!data_size && !text_size && link_once_size) 
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		code_segment_size =
			link_once_size - (unsigned long)(mod->core_layout.base);
#else
		code_segment_size =
			link_once_size - (unsigned long)(mod->module_core);
#endif
	} 
	else 
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "modules[%s], code_segment_size error! text_size[%lu], data_size[%lu], link_once_size[%lu]\n",
			mod->name, text_size, data_size, link_once_size);
	}
out:
	return code_segment_size;
}


static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char* hash)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}
	//if (path) {
	if (point) {
		//memcpy(sec_d->sub_name, path, strlen(path));
		memcpy(sec_d->sub_name, point->name, strlen(point->name));
	} else {
		memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	}
	
	if (result==RESULT_FAIL) {
		memcpy(sec_d->obj_name, "module_list(", strlen("module_list("));
		memcpy(sec_d->obj_name+strlen(sec_d->obj_name), name, strlen(name));
		memcpy(sec_d->obj_name+strlen(sec_d->obj_name), ")", 1);
	}
	else
		memcpy(sec_d->obj_name, name, strlen(name));
	//memset(sec_d->sub_hash, 0, LEN_HASH);
	memcpy(sec_d->sub_hash, hash, LEN_HASH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (point) {
		keraudit_log(TYPE_DMEASURE, point->type, result, sec_d, user,
			     current->pid);
	} else {
		keraudit_log(TYPE_DMEASURE, DMEASURE_OPERATE_PERIODICITY, result, sec_d,
			     user, current->pid);
	}

	kfree(sec_d);

out:
	return ret;
}

static int httcsec_mod_memcmp(const void *cs, const void *ct, size_t count,size_t * offset)//copy from section
{
	const unsigned char *su1, *su2;
	int res = 0;
	size_t off = 0;
			  
    for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--, off++)
		if ((res = *su1 - *su2) != 0)
			break;
	*offset = off;
	return res;
}

//match return 1; else xxx
static int match_jumplable_code(unsigned long addr,struct jump_entry *entries,unsigned int num_entries)
{
	int ret = 0;
	int index = 0;
	struct jump_entry *p = NULL;

	if((entries == NULL) || (num_entries == 0)){
		ret = -1;
		goto out;
	}

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	addr &= (~3UL);
#endif

	for(index=0,p = entries;index < num_entries;index++,p++)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
		if (addr == jump_entry_code(p))
#else
		if(addr == p->code)
#endif
		{
			ret = 1;
			break;
		}

	}



out:
	return ret;
}


int module_list_check(void *data)
{
	int ret = 0;
	size_t offset;
	size_t base_offset;
	struct module_info *mod_info = NULL;
	struct module *mod = NULL;
	unsigned code_segment_size = 0;
	struct dmeasure_point *point = NULL;
	unsigned char sm3_hash[32] = {0};
	sm3_context ctx;

	

	if (data) {
		//path = (char *)data;
		point = (struct dmeasure_point *)data;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_lock(&module_mutex);
#endif
	list_for_each_entry(mod_info, &module_list, list) 
	{
		mod = mod_info->mod;

		if (mod_info->mod->state == MODULE_STATE_LIVE
		    /*&& check_in_policy(mod->name)*/) 
		{
			 struct jump_entry *entries;
                 	unsigned int num_entries;
			//code_segment_size = cal_module_code_segment_size(mod);
			offset = 0;
			base_offset = 0;
			entries = mod->jump_entries;
			num_entries = mod->num_jump_entries;
			
			code_segment_size = mod_info->len_base;
			sm3_init(&ctx);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
			//code_crc32 = crc32(~0, mod->core_layout.base, code_segment_size);
			sm3_update(&ctx, mod->core_layout.base, code_segment_size);
#else
			//code_crc32 = crc32(~0, mod->module_core, code_segment_size);
			sm3_update(&ctx, mod->module_core, code_segment_size);
#endif
			sm3_finish(&ctx, sm3_hash);

			if (memcmp(sm3_hash, mod_info->sm3_hash, 32) == 0) 
			{
				
			} else {

				if(num_entries == 0){
					DEBUG_MSG(HTTC_TSB_INFO, "[%s], kernel module[%s] is changed!\n", __func__, mod->name);
					CriticalDataFailureCount_add();
					send_audit_log(point, mod->name, RESULT_FAIL, sm3_hash);
					ret = -EINVAL;

				}else if(num_entries > 0){
					while(1){
				

						httcsec_mod_memcmp(mod->core_layout.base+base_offset,mod_info->base+base_offset,mod_info->len_base,&offset);
						if(match_jumplable_code((unsigned long )mod->core_layout.base+base_offset+offset,entries,num_entries) == 1){

							base_offset += offset;
#if defined(__x86_64__)
							base_offset += 5;
#else
							base_offset += 4;
#endif	

							if(base_offset >= code_segment_size){
								break;
							}
							
						}else{
							ret = -EINVAL;
							break;
						}

						

					}
				}
			}
		}
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_unlock(&module_mutex);
#endif
	if (!ret) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure Module_list success!\n", __func__);
		memset(sm3_hash, 0, LEN_HASH);
		send_audit_log(point, "module_list", RESULT_SUCCESS, sm3_hash);
	}

	return ret;
}

static int module_in_basedata(struct module *mod)
{
	struct module_info *tmp = NULL;

	list_for_each_entry(tmp, &module_list, list) {
		if (mod == tmp->mod)
			return 1;
	}
	return 0;
}

static int is_httcsec_module(const char *modname)
{
	int ret = 0;

	if (!strcmp(modname, "platform") ||
	    !strcmp(modname, "httcdmeasure") ||
	    !strcmp(modname, "httcsmeasure") ||
		!strcmp(modname, "httcfac")) {
		ret = 1;
	}

	return ret;
}

static int add_module_dmeasure(struct module *mod)
{
	int ret = 0;
	struct module_info *mod_info = NULL;
	unsigned long code_segment_size = 0;
	//unsigned int code_crc32 = 0;
	unsigned char sm3_hash[32] = {0};
	sm3_context ctx;

	if (is_httcsec_module(mod->name))
		goto out;


	code_segment_size = cal_module_code_segment_size(mod);
	if (code_segment_size == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "------Module Info Name:[%s], code_size:[%lu], error!------\n", mod->name, code_segment_size);
		ret = -EINVAL;
		goto call_size;
	}

	mod_info = kzalloc(sizeof(struct module_info)+code_segment_size, GFP_ATOMIC);
	if (!mod_info) {
		ret = -ENOMEM;
		goto out;
	}

	mod_info->len_base = code_segment_size;
	mod_info->mod = mod;
	strcpy(mod_info->name, mod->name);
	

	sm3_init(&ctx);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	//code_crc32 = crc32(~0, mod->core_layout.base, code_segment_size);
	sm3_update(&ctx, mod->core_layout.base, code_segment_size);
#else
	//code_crc32 = crc32(~0, mod->module_core, code_segment_size);
	sm3_update(&ctx, mod->module_core, code_segment_size);
#endif
	sm3_finish(&ctx, sm3_hash);
	//mod_info->code_crc32 = code_crc32;
	memcpy(mod_info->sm3_hash, sm3_hash, 32);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)	
	memcpy(mod_info->base, mod->core_layout.base, mod_info->len_base);
#else
	memcpy(mod_info->base, mod->module_core, mod_info->len_base);
#endif

	dmodule_count++;
	list_add(&mod_info->list, &module_list);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Add Module Info Name:[%s], code_size:[%lu]\n", mod->name, code_segment_size);
	goto out;

call_size:
	if(mod_info){
		kfree(mod_info);
	}
out:
	return ret;
}

static int add_all_module_info(void)
{
	int ret = 0;
	struct module *mod = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_lock(&module_mutex);
#endif
	list_for_each_entry(mod, sys_modules, list) {
		if (mod->state != MODULE_STATE_GOING
		    && !module_in_basedata(mod)) {
			add_module_dmeasure(mod);
		}
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "[%s], dmodule count:[%d]\n", __func__, dmodule_count);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_unlock(&module_mutex);
#endif
	return ret;
}

static int remove_all_module_info(void)
{
	struct module_info *mod_info = NULL, *tmp = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_lock(&module_mutex);
#endif
	list_for_each_entry_safe(mod_info, tmp, &module_list, list) {
		dmodule_count--;
		list_del(&mod_info->list);
		kfree(mod_info);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
	mutex_unlock(&module_mutex);
#endif
	DEBUG_MSG(HTTC_TSB_DEBUG, "[%s] dmodule_count:[%d]\n", __func__, dmodule_count);
	return 0;
}

static int del_module_dmeasure(struct module *mod)
{
	int ret = 0;
	struct module_info *mod_info, *tmp;

	list_for_each_entry_safe(mod_info, tmp, &module_list, list) {
		if (mod_info->mod == mod) {
			DEBUG_MSG(HTTC_TSB_DEBUG, "Remove Module Info name:%s\n", mod->name);
			list_del(&mod_info->list);
			kfree(mod_info);
			dmodule_count--;
			DEBUG_MSG(HTTC_TSB_DEBUG, "[%s], dmodule count:[%d]\n", __func__,
				dmodule_count);
			break;
		}
	}

	return ret;
}

static int handle_module_notifier(struct notifier_block *nb, unsigned long val,
				  void *data)
{
	int ret = 0;
	struct module *mod = (struct module *)data;

	switch (val) {
	case MODULE_STATE_LIVE:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_lock(&module_mutex);
#endif
		add_module_dmeasure(mod);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_unlock(&module_mutex);

#endif
		break;
	case MODULE_STATE_GOING:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_lock(&module_mutex);
#endif
		del_module_dmeasure(mod);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_unlock(&module_mutex);
#endif
		break;
	default:
		break;
	}

	return ret;
}

static struct notifier_block module_state = {
	.notifier_call = handle_module_notifier
};

static struct dmeasure_node dmodule_action = {
	.name = ACTION_NAME,
	.check = module_list_check,
};

int modules_init(void)
{
	int ret = 0;

	ret = kernel_args_addr_init();
	if (ret)
		goto out;

	modules_p = kzalloc(sizeof(struct modules_policy), GFP_KERNEL);
	if (!modules_p) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc modules policy err!\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = add_all_module_info();
	if (ret) {
		ret = -EINVAL;
		goto out_module_info;
	}

	ret = register_module_notifier(&module_state);
	if (ret) {
		ret = -EINVAL;
		goto out_register;
	}

	//get_modules_policy(modules_p);
	ret = dmeasure_register_action(DMEASURE_MODULE_ACTION, &dmodule_action);
	if (ret) {
		ret = -EINVAL;
		goto out_action;
	}

	return ret;

out_action:
	unregister_module_notifier(&module_state);
out_register:
	remove_all_module_info();
out_module_info:
	kfree(modules_p);
out:
	return ret;
}

void modules_exit(void)
{
	if (modules_p)
		kfree(modules_p);
	dmeasure_unregister_action(DMEASURE_MODULE_ACTION, &dmodule_action);
	unregister_module_notifier(&module_state);
	remove_all_module_info();
	DEBUG_MSG(HTTC_TSB_DEBUG,"######################### dmeasure modules exit!\n");
	return;
}

