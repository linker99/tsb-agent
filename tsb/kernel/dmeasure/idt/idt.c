#if defined(__x86_64__)
#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/desc.h>
#include <linux/skbuff.h>
#include <linux/cred.h>
#include "../dmeasure/memcmp_action.h"
#include "dmeasure_types.h"
#include "version.h"
//#include "policy/list_dmeasure_trigger.h"
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
#include "tpcm/tpcmif.h"
#include "sec_domain.h"
#include "function_types.h"
#include "log/log.h"
#include "../policy/policy_dmeasure.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "../utils/traceability.h"
#include "utils/debug.h"

static unsigned long idt_addr = INVALID_DATA_FULL_FF;
module_param(idt_addr, ulong, 0644);
MODULE_PARM_DESC(idt_addr, "ulong idt address");

static unsigned long idt_start_address;
static int idt_length;
//static struct memcmp_action *memcheck;

struct idt_measure {
	unsigned long *idt_addr;
	int len_base;
	unsigned char hash[LEN_HASH];
	//char base[0];
};
struct idt_measure *idt_m;

/* #define ACTION_NAME	"Idt_table" */
//#define CIRCLE_NAME   "Periodicity"
#define ACTION_NAME	DM_ACTION_IDTTABLE_NAME

//static struct dmeasure_feature_conf *dmeasure_feature = NULL;

static int backup_idt(void)
{
	int ret = 0;
	struct desc_ptr idt;
	struct dmeasure_feature_conf *dmeasure_feature;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	store_idt(&idt);
	//native_store_idt(&idt);

	//if ((unsigned long)idt.address < (unsigned long)PAGE_OFFSET) {
	//        printk("idt_addr:[%0lx]!\n", idt_addr);
	//        idt_start_address = idt_addr;
	//} else {
	//        idt_start_address = idt.address;
	//}
	idt_start_address = idt_addr;
	idt_length = idt.size;

	dmeasure_feature = get_dmeasure_feature_conf();
	if(dmeasure_feature->measure_mode)
		ret = set_measure_zone_to_tpcm(ACTION_NAME, (void *)idt_start_address, idt_length);
	/* if (ret) { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm error !\n", */
	/* 	       __func__); */
	/* 	goto out; */
	/* } else { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm success !\n", */
	/* 	       __func__); */
	/* } */

	idt_m = kzalloc(sizeof(struct idt_measure), GFP_KERNEL);
	if (!idt_m) {
		ret = -ENOMEM;
		goto out;
	}

	idt_m->idt_addr = (unsigned long *)idt_start_address;
	idt_m->len_base = idt_length;
	//memcpy(idt_m->base, (unsigned long *)idt_start_address, idt_length);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], idt_addr:[%0lx], idt_length:[%d]\n", __func__,
		(unsigned long)idt_start_address, idt_length);
	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)idt_start_address, idt_length);
	sm3_finish(&ctx, hash);
	print_hex(ACTION_NAME, hash, LEN_HASH);
	memcpy(idt_m->hash, hash, LEN_HASH);

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

int idt_table_check(void *data)
{
	int ret = 0;
	struct dmeasure_point *point = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	if (data) {
		point = (struct dmeasure_point *)data;
	}

	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)idt_m->idt_addr, idt_m->len_base);
	sm3_finish(&ctx, hash);

	//ret = memcmp(idt_m->idt_addr, idt_m->base, idt_m->len_base);
	if (memcmp(hash, idt_m->hash, LEN_HASH) == 0) {
		send_audit_log(point, ACTION_NAME, RESULT_SUCCESS, hash);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure idt table success!\n", __func__);
	} else {
		send_audit_log(point, ACTION_NAME, RESULT_FAIL, hash);
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure idt table error!\n", __func__);
		ret = -EACCES;
	}

	return ret;
}

static struct dmeasure_node didt_action = {
	.name = ACTION_NAME,
	.check = idt_table_check,
};

int idt_init(void)
{
	int ret = 0;

	if (idt_addr == INVALID_DATA_FULL_FF || idt_addr == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [IDT] Argument Error!\n");
		ret = -EINVAL;
		goto out;
	}

	//dmeasure_feature = get_dmeasure_feature_conf();

	ret = backup_idt();
	if (ret)
		goto out;

	//if(dmeasure_feature->measure_mode)
	//{
	//	printk("dmeasure idt using tpcm\n");
	//	goto out;
	//}

	//printk("dmeasure idt using soft\n");
	dmeasure_register_action(DMEASURE_IDT_ACTION, &didt_action);

out:
	return ret;
}

void idt_exit(void)
{
	if (idt_m)
		kfree(idt_m);

	dmeasure_unregister_action(DMEASURE_IDT_ACTION, &didt_action);
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure idt exit!\n");
	return;
}
#endif
