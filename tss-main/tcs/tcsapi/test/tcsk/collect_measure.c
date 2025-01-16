#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tdd.h"
#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("TPCM_CollectAndMeasure test");

static char *dmname = NULL;

struct sctl_switch {
        char name[32];
        int sctl_on;
};

struct sctl_switch sctl_sw = { 
        .name = "TSB_SWITCH",
        .sctl_on = 0x01020304,

};

enum {
	DMT_TSB = 0,
	DMT_IDT_TABLE,
	DMT_KERNEL_SECTION,
	DMT_SYS_CALL_TABLE,
};

void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod collect_measure.ko [dmname=NAME]\n");
	printk ("    eg. insmod collect_measure.ko\n");
	printk ("    eg. insmod collect_measure.ko dmname=idt_table\n");
	printk ("    eg. insmod collect_measure.ko dmname=kernel_section\n");
	printk ("    eg. insmod collect_measure.ko dmname=syscall_table\n");
	printk ("\n");
}

int test_CollectAndMeasure (void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint32_t operation = OP_CTX_DM_INIT_COLLECT;
	uint64_t ctxNumber = 0;
	struct collection_context ctx[5];
	uint32_t mrLen = 256;
	uint8_t mresult[256] = {0};
	uint8_t *cm_ptr_start = NULL;
	uint8_t *cm_ptr_end = NULL;
	struct sctl_switch *tsb_test = NULL;
	//struct desc_ptr dt;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)) || (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
	unsigned long (*httc_kallsyms_lookup_name) (const char *name) = (void *)k_kallsyms_lookup_name;
#else
	unsigned long (*httc_kallsyms_lookup_name) (const char *name) = kallsyms_lookup_name;
#endif

	memset (ctx, 0, sizeof (struct collection_context) * 5);
	
	if (NULL == dmname){
		/** syscall_table */
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name ("sys_call_table"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(%s) failed!\n", __func__, __LINE__, "syscall_table");
			goto kernel_section;
		}
		memset (&ctx[ctxNumber], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_SYS_CALL_TABLE;
		ctx[ctxNumber].name_length = strlen ("syscall_table") + 1;
		memcpy (ctx[ctxNumber].name, "syscall_table", ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = 128;//__NR_syscalls;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);
		ctxNumber ++;
		
kernel_section:
		/** kernel_section */
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name ("_stext"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(_stext) failed!\n", __func__, __LINE__);
			goto idt_table;
		}
		if (NULL == (cm_ptr_end = (uint8_t *)httc_kallsyms_lookup_name ("_etext"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(_etext) failed!\n", __func__, __LINE__);
			goto idt_table;
		}

		memset (&ctx[ctxNumber], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_KERNEL_SECTION;
		ctx[ctxNumber].name_length = strlen ("kernel_section") + 1;
		memcpy (ctx[ctxNumber].name, "kernel_section", ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = cm_ptr_end - cm_ptr_start;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);
		ctxNumber ++;

idt_table:
		/** idt_table */
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name ("idt_table"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(%s) failed!\n", __func__, __LINE__, "idt_table");
			goto cmd;
		}

		memset (&ctx[ctxNumber], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_IDT_TABLE;
		ctx[ctxNumber].name_length = strlen ("idt_table") + 1;
		memcpy (ctx[ctxNumber].name, "idt_table", ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = 128;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);
		ctxNumber ++;
	}
	else if (!strcmp (dmname, "idt_table")){
		//store_idt (&dt);
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name (dmname))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(%s) failed!\n", __func__, __LINE__, dmname);
			return -EINVAL;
		}

		memset (&ctx[ctxNumber], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_IDT_TABLE;
		ctx[ctxNumber].name_length = strlen ("idt_table") + 1;
		memcpy (ctx[ctxNumber].name, "idt_table", ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = 128;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);		
		ctxNumber ++;
	}
	else if (!strcmp (dmname, "kernel_section")){
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name ("_stext"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(_stext) failed!\n", __func__, __LINE__);
			return -EINVAL;
		}
		if (NULL == (cm_ptr_end = (uint8_t *)httc_kallsyms_lookup_name ("_etext"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(_etext) failed!\n", __func__, __LINE__);
			return -EINVAL;
		}
		memset (&ctx[0], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_KERNEL_SECTION;
		ctx[ctxNumber].name_length = strlen (dmname) + 1;
		memcpy (ctx[ctxNumber].name, dmname, ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = cm_ptr_end - cm_ptr_start;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);	
		ctxNumber ++;
	}
	else if (!strcmp (dmname, "syscall_table")){
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kallsyms_lookup_name ("syscall_table"))){
			printk ("[%s:%d] httc_kallsyms_lookup_name(%s) failed!\n", __func__, __LINE__, dmname);
			return -EINVAL;
		}
		memset (&ctx[0], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_SYS_CALL_TABLE;
		ctx[ctxNumber].name_length = strlen (dmname) + 1;
		memcpy (ctx[ctxNumber].name, dmname, ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = 128;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);	
		ctxNumber ++;
	}
	else if (!strcmp (dmname, "tsb_test")){
		if (NULL == (cm_ptr_start = (uint8_t *)httc_kmalloc (sizeof(sctl_sw),GFP_KERNEL))){
			printk ("[%s:%d] httc_kmalloc(%s) failed!\n", __func__, __LINE__, "tsb_test");
			return -EINVAL;
		}
		
		memcpy(cm_ptr_start,&sctl_sw,sizeof(sctl_sw));

		memset (&ctx[0], 0, sizeof (struct collection_context));
		ctx[ctxNumber].type = DMT_TSB;
		ctx[ctxNumber].name_length = strlen (dmname) + 1;
		memcpy (ctx[ctxNumber].name, dmname, ctx[ctxNumber].name_length);
		ctx[ctxNumber].data_length = 128;
		ctx[ctxNumber].data_address = tdd_get_phys_addr(cm_ptr_start);	
		ctxNumber ++;
	}
	else{
		usage ();
		return -EINVAL;
	}

cmd:
	ret = tcsk_collection_and_measure (operation, ctxNumber, ctx, &tpcmRes, &mrLen, mresult);
	printk ("[%s:%d]ret: 0x%08x, tpcmRes: 0x%08x\n", __func__, __LINE__, ret, tpcmRes);
	if ((0 == ret) && (0 != mrLen)) httc_util_dump_hex ("mresult", mresult, mrLen);
	if (ret || tpcmRes)	ret = -1;
	if (NULL != dmname && !strcmp (dmname, "tsb_test")){		
		tsb_test = (struct sctl_switch *)cm_ptr_start;
		tsb_test->sctl_on = 0x01020303;
		}
	return ret;
}

int collect_memasure_init(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
	return test_CollectAndMeasure();
}

void collect_memasure_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_param(dmname, charp,  S_IRUGO | S_IWUSR);


module_init(collect_memasure_init);
module_exit(collect_memasure_exit);

