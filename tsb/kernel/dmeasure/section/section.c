#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/cred.h>
#include <linux/sort.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#include <linux/kprobes.h>
#endif

#include "dmeasure_types.h"
/* #include "memory_protection.h" */
#include "version.h"
#include "../dmeasure/memcmp_action.h"
//#include "policy/list_dmeasure_trigger.h"
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
//#include "tpcmif.h"
#include "../utils/traceability.h"
#include "sec_domain.h"
#include "function_types.h"
#include "tpcm/tpcmif.h"
#include "log/log.h"
#include "../policy/policy_dmeasure.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "utils/debug.h"

typedef u64 jump_label_t;

static unsigned long start_text = INVALID_DATA_FULL_FF;
static unsigned long end_text = INVALID_DATA_FULL_FF;
static unsigned long t_lookup_symbol_name = INVALID_DATA_FULL_FF;
module_param(start_text, ulong, 0644);
module_param(end_text, ulong, 0644);
MODULE_PARM_DESC(start_text, "ulong start_text address");
MODULE_PARM_DESC(end_text, "ulong end_text address");
module_param(t_lookup_symbol_name, ulong, 0644);
MODULE_PARM_DESC(t_lookup_symbol_name, "ulong lookup_symbol_name address");

int (*kernel_lookup_symbol_name) (unsigned long addr, char *symname);

struct ksection_measure {
	unsigned long *ksection_addr;
	int len_base;
	unsigned char hash[LEN_HASH];
	char base[0];
};

struct ksection_measure *ksection_m;

//#define ACTION_NAME   "Kernel_section"
//#define CIRCLE_NAME   "Periodicity"
#define ACTION_NAME	DM_ACTION_KSECTION_NAME

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
int dmeasure_pre(struct kprobe *p, struct pt_regs *regs) 
{ 
	return 0;
}

static struct kprobe kp = 
{
	.symbol_name = "kallsyms_lookup_name",
};

unsigned long (*kallsyms_lookup_name_fun)(const char *name) = NULL;

int find_kallsyms_lookup_name(void)
{
	int ret = -1;
	unsigned long *sym_address;
	kp.pre_handler = dmeasure_pre;
	ret = register_kprobe(&kp);
	if (ret < 0)
	{
			DEBUG_MSG(HTTC_TSB_INFO, "register_kprobe failed, error:%d\n", ret);
			return ret;
	}
	sym_address = (void *)kp.addr;
	DEBUG_MSG(HTTC_TSB_DEBUG, "find_module_fun addr: %p\n", ((void*)kp.addr));
	DEBUG_MSG(HTTC_TSB_DEBUG, "sym_address %px\n", (void*)sym_address);
	//find_module_fun = (void*)kp.addr;
	kallsyms_lookup_name_fun = (void*)sym_address;
	unregister_kprobe(&kp);
	return ret;

}
#endif

static unsigned long* section_jump_entry=NULL;
static int section_jump_entry_size = 0;

//static struct dmeasure_feature_conf *dmeasure_feature = NULL;

static int section_jump_entry_binary_search(unsigned long code)
{
	int left = 0;
	int right = section_jump_entry_size - 1;

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	code &= (~3UL);
#endif


	while (left <= right) {
		int mid = left + (right - left) / 2;
		
		if (section_jump_entry[mid] < code) {
			left = mid + 1;
		}
		
		else if (code < section_jump_entry[mid]) {
			right = mid - 1;
		}
		else 
			return mid;
	}
	return -1;
}

static int backup_ksection(void)
{
	int ret = 0;
	unsigned long data_len = 0;
	struct dmeasure_feature_conf *dmeasure_feature;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	data_len = end_text - start_text;

	/* set_memory_unit(TYPE_KERNEL_SECTION, DM_ACTION_KSECTION_NAME, */
	/* 		(void *)start_text, data_len); */

	dmeasure_feature = get_dmeasure_feature_conf();
	if(dmeasure_feature->measure_mode)
		ret = set_measure_zone_to_tpcm(ACTION_NAME, (void *)start_text, data_len);
	/* if (ret) { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm error !\n", */
	/* 	       __func__); */
	/* 	goto out; */
	/* } else { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm success !\n", */
	/* 	       __func__); */
	/* } */

	ksection_m = vzalloc(sizeof(struct ksection_measure) + data_len);
	if (!ksection_m) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vzalloc:[%lu] error!\n", __func__,sizeof(struct ksection_measure));
		ret = -ENOMEM;
		goto out;
	}

	ksection_m->ksection_addr = (unsigned long *)start_text;
	ksection_m->len_base = data_len;
	memcpy(ksection_m->base, (unsigned long *)start_text, data_len);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], ksection_addr:[%0lx], ksection_length:[%lu]\n",__func__, (unsigned long)start_text, data_len);

	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)start_text, data_len);
	sm3_finish(&ctx, hash);
	print_hex(ACTION_NAME, hash, LEN_HASH);
	memcpy(ksection_m->hash, hash, LEN_HASH);

out:
	return ret;
}

static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char* hash)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	//TODO
	//if (!is_allowed_send_log(result))
	//	return 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	//if (point) {
	//	memcpy(sec_d->sub_name, point->name, strlen(point->name));
	//} else {
	//	memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	//}
	memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
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

static int httcsec_memcmp(const void *cs, const void *ct, size_t count,
			  size_t * offset)
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

#if defined(__x86_64__)
static int httc_core_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)start_text && addr < (unsigned long)end_text)
		return 1;

	return 0;
}
#endif

static int httc_analyse_abnormal(char *addr)
{
	int ret = 0;
	unsigned char val = *addr;
#if defined(__x86_64__)
	int offset = 0;
	struct module *mod = NULL;
#endif

	switch (val) {
#if defined(__x86_64__)
	case 0xe9:		// jump
		offset = *(int *)(addr + 1);
		if (httc_core_kernel_text((unsigned long)(addr + 5 + offset))) {
			ret = 1;	// kernel
		} else {
			mod =
			    get_module_from_addr((unsigned long)(addr + 5 +
								 offset));
			if (mod) {
				DEBUG_MSG(HTTC_TSB_DEBUG, "Hooked by %s\n", mod->name);
				ret = 2;	// module
			}

			ret = 3;	// other
		}
		break;
	case 0x0f:		// maybe nop
		ret = 1;
		break;
#elif defined (CONFIG_ARM)
	case 0x90:		// nop
		ret = 1;
		break;

#endif
	default:
		ret = 3;	// other
		DEBUG_MSG(HTTC_TSB_DEBUG, "dump val: 0x%x\n", val);
		break;
	}

	return ret;
}



static int lookup_abnormal_symbol_name(int off, struct dmeasure_point *point)
{

	size_t offset = 0;
	size_t base_offset = off;
	char symname[KSYM_NAME_LEN] = { 0 };
	char last_symname[KSYM_NAME_LEN] = { 0 };
	int section_error = 0;

	while (1) {

		int  is_jump_lable = 0;
		if(section_jump_entry_binary_search((unsigned long)ksection_m->ksection_addr + base_offset) >= 0)
			is_jump_lable = 1;

		memset(symname, 0, KSYM_NAME_LEN);
		if (kernel_lookup_symbol_name((unsigned long)ksection_m->ksection_addr + base_offset, symname) < 0) {
			//printk("lookup_symbol_name return err [%ld]!\n", offset);
		} else if (strncmp(last_symname, symname, strlen(symname)) != 0) {
			//send_audit_log(point, symname, RESULT_FAIL);


			if(is_jump_lable) {
				DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure kernel section success[%s][%d](jump_entry address skip)\n",
					__func__, symname, httc_analyse_abnormal((char*)ksection_m->ksection_addr + base_offset));

			} else {

				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure kernel section error[%s][%d]!\n",
					__func__, symname, httc_analyse_abnormal((char*)ksection_m->ksection_addr + base_offset));
				section_error = 1;
			}


			strncpy(last_symname, symname, strlen(symname));

		}
#if defined(__x86_64__)
		base_offset += 5;
#else
		base_offset += 4;
#endif
		if (base_offset >= ksection_m->len_base)
			break;

		if (httcsec_memcmp((void *)((unsigned long)ksection_m->ksection_addr+base_offset), (void *)((unsigned long)ksection_m->base+base_offset), ksection_m->len_base-base_offset, &offset) == 0)
			break;

		base_offset += offset;
	}

	return section_error;
}

int kernel_section_check(void *data)
{
	int ret = 0;
	size_t offset = 0;
	struct dmeasure_point *point = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	if (data) {
		point = (struct dmeasure_point *)data;
	}

	//ret =
	//    httcsec_memcmp(ksection_m->ksection_addr, ksection_m->base,
	//		   ksection_m->len_base, &offset);

	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)ksection_m->ksection_addr, ksection_m->len_base);
	sm3_finish(&ctx, hash);
	//print_hex("hash", hash, LEN_HASH);
	//memcpy(ksection_m->hash, hash, LEN_HASH);

	if (memcmp(hash, ksection_m->hash, LEN_HASH) == 0) {
		send_audit_log(point, ACTION_NAME, RESULT_SUCCESS, hash);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure kernel section success!\n",__func__);
	} else {
		httcsec_memcmp(ksection_m->ksection_addr, ksection_m->base, ksection_m->len_base, &offset);
		if(lookup_abnormal_symbol_name(offset, point)) {
			SectionFailureCount_add();
			send_audit_log(point, ACTION_NAME, RESULT_FAIL, hash);
			ret = -EACCES;
		}
		else
			send_audit_log(point, ACTION_NAME, RESULT_SUCCESS, hash);
		//printk("Enter:[%s], dmeasure kernel section error!\n", __func__);
		//ret = -EACCES;
	}

	return ret;
}

int jump_entry_check(void)
{
	size_t offset = 0;

	httcsec_memcmp(ksection_m->ksection_addr, ksection_m->base, ksection_m->len_base, &offset);
	return lookup_abnormal_symbol_name(offset, NULL);
}

static struct dmeasure_node dksection_action = {
	.name = ACTION_NAME,
	.check = kernel_section_check,
};

static int section_jump_entry_cmp(const void *a, const void *b)
{
	const unsigned long *jea = a;
	const unsigned long *jeb = b;

	if (*jea < *jeb)
			return -1;

	if (*jea> *jeb)
			return 1;

	return 0;
}




#if defined(CONFIG_64BIT)
#define  INVALID_DATA_FULL_FF   0xffffffffffffffff
#else
#define  INVALID_DATA_FULL_FF   0xffffffff
#endif

unsigned long (*get_kallsyms_lookup_name) (const char *name);
unsigned long t_kallsyms_lookup_name = INVALID_DATA_FULL_FF;
module_param(t_kallsyms_lookup_name, ulong, 0644);
EXPORT_SYMBOL_GPL(t_kallsyms_lookup_name);




int section_init(void)
{
	int ret = 0;
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10, 0)
	get_kallsyms_lookup_name = (void *)t_kallsyms_lookup_name;
#else
unsigned long (*get_kallsyms_lookup_name) (const char *name) = kallsyms_lookup_name;

#endif
	struct jump_entry* iter = NULL;
	unsigned long* p_node = NULL;


	unsigned long start_adr = get_kallsyms_lookup_name("__start___jump_table");
	unsigned long stop_adr = get_kallsyms_lookup_name("__stop___jump_table");
	struct jump_entry *iter_start = (struct jump_entry*)start_adr;
	struct jump_entry *iter_stop = (struct jump_entry*)stop_adr;

	if (start_text == INVALID_DATA_FULL_FF || start_text == 0 ||
	    end_text == INVALID_DATA_FULL_FF || end_text == 0 ||
	    t_lookup_symbol_name == INVALID_DATA_FULL_FF
	    || t_lookup_symbol_name == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [SECTION] Argument Error!\n");
		ret = -EINVAL;
		goto out;
	} else {
		kernel_lookup_symbol_name = (void *)t_lookup_symbol_name;
		DEBUG_MSG(HTTC_TSB_DEBUG, "start_text:[%0lx], end_text:[%0lx]!\n", start_text,end_text);
	}

	if (iter_start==NULL || iter_stop==NULL) {
			DEBUG_MSG(HTTC_TSB_INFO, "__start___jump_table or __stop___jump_table sym find error!\n");
			ret = -EINVAL;
			goto out;
	}

	section_jump_entry_size = (stop_adr - start_adr ) / sizeof(struct jump_entry);
	DEBUG_MSG(HTTC_TSB_DEBUG, "start___jump_table:lx[%0lx],  stop___jump_table:lx[%0lx] section_jump_entry_size[%d]\n", (unsigned long)iter_start, (unsigned long)iter_stop, section_jump_entry_size);
	p_node = section_jump_entry = kmalloc(section_jump_entry_size * sizeof(unsigned long), GFP_KERNEL);
	for (iter = iter_start; iter < iter_stop; iter++) 
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
		*p_node = jump_entry_code(iter);
#else
		* p_node = iter->code;
#endif
		
		p_node++;
	}
	sort(section_jump_entry, section_jump_entry_size, sizeof(unsigned long), section_jump_entry_cmp, NULL);

	ret = backup_ksection();
	if (ret) {
		DEBUG_MSG(HTTC_TSB_INFO, "backup ksection error!\n");
		goto out;
	}


	jump_entry_check_func_register(jump_entry_check);

	ret = dmeasure_register_action(DMEASURE_SECTION_ACTION, &dksection_action);
	if (ret == 0)
		DEBUG_MSG(HTTC_TSB_DEBUG, "register kernel section success!\n");
	else
		DEBUG_MSG(HTTC_TSB_INFO, "register kernel section error!\n");
out:
	return ret;
}

void section_exit(void)
{
	jump_entry_check_func_unregister(jump_entry_check);

	if (ksection_m)
		vfree(ksection_m);

	dmeasure_unregister_action(DMEASURE_SECTION_ACTION, &dksection_action);
	kfree(section_jump_entry);
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure section exit!\n");
	return;
}
