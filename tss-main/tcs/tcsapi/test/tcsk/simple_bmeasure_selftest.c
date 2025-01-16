#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_tpcm.h"
#include "tcs_constant.h"
#include "sm3.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_simple_boot_measure test");

#define BM_BLOCK_LIMIT	50

static int addr_num = 3;
static unsigned int stage = 2999; 
static char *obj = "SELFTEST"; 
static unsigned char* addr[BM_BLOCK_LIMIT] = {0};
static unsigned int length[BM_BLOCK_LIMIT] = {0};

#define BM_TEST_SIZE	0x1000

static int brief_bmeasure_selftest_init (void)
{
	int i = 0;
	for (i = 0; i < addr_num; i++){
		length[i] = BM_TEST_SIZE * (i+1);
		if (0 == (addr[i] = httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
			printk ("Kmalloc for addr[%d] failed!\n", i);
			for (; i >= 0; i--)
				if (addr[i]) httc_kfree (addr[i]);
			return -ENOMEM;
		}		
	}

	return 0;
}

static void brief_bmeasure_selftest_exit (void)
{
	int i = 0;
	for (i = 0; i < addr_num; i++){
		if (addr[i]) httc_kfree (addr[i]);		
	}
}


static int brief_bmeasure (uint32_t *tpcmRes)
{
	int i = 0;
	int ret = 0;
	uint32_t objLen = strlen (obj) + 1;
	uint8_t digest[DEFAULT_HASH_SIZE] = {0};
	sm3_context ctx;
	if(!tpcmRes) return -1;
	
	if (addr_num > BM_BLOCK_LIMIT){
		printk ("Invalid Param: addr_num is too large.\n\n");
		return -EINVAL;
	}

	httc_sm3_init (&ctx);
	for (i = 0; i < addr_num; i++){
		 httc_sm3_update (&ctx, addr[i], length[i]);
	}
	httc_sm3_finish (&ctx, digest);
	
	ret = tcsk_simple_boot_measure (stage, digest, (uint8_t *)obj, objLen, tpcmRes);
	printk ("[tcsk_simple_boot_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, *tpcmRes);
	if (ret || *tpcmRes)	ret = -1;

	return ret;
}

int __brief_bmeasure_selftest_init__(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;

	printk ("[%s:%d]\n", __func__, __LINE__);

	if (0 != (ret = brief_bmeasure_selftest_init ()))	goto faliure;

	ret = brief_bmeasure (&tpcmRes);

faliure:
	brief_bmeasure_selftest_exit ();
	return ret;
}


void __brief_bmeasure_selftest_exit__(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init(__brief_bmeasure_selftest_init__);
module_exit(__brief_bmeasure_selftest_exit__);

