#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tdd.h"
#include "memdebug.h"
#include "tcs_tpcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_boot_measure test");

#define BM_BLOCK_LIMIT	50

//static int addr_num = 3;
//static int length_num = 3;
//static unsigned int stage = 9999;
//static char *obj = "SELFTEST";
static unsigned long addr[BM_BLOCK_LIMIT] = {0};
//static unsigned int length[BM_BLOCK_LIMIT] = {0};

static void usage (void)
{
	printk ("\n");
	printk (" Usage: insmod boot_measure_selftest.ko\n");
	printk ("\n");
}

#define BM_TEST_SIZE	0x1000

int boot_measure_selftest(char *obj,int addr_num,int stage,int value)
{
	int i = 0;
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct physical_memory_block block[BM_BLOCK_LIMIT];
	uint8_t *objAddress = NULL;
	uint32_t objLen = 0;
	
	printk ("[%s:%d]\n", __func__, __LINE__);
//	if ((NULL == obj) || (0 == addr_num) || (-1 == stage)){
//		usage ();
//		return -EINVAL;
//	}
//	if (addr_num != length_num){
//		printk ("Invalid Param: addr_num != length_num.\n\n");
//		usage ();
//		return -EINVAL;
//	}
	if (addr_num > BM_BLOCK_LIMIT){
		printk ("Invalid Param: addr_num != length_num.\n\n");
		usage ();
		return -EINVAL;
	}

	if (NULL == (objAddress = httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
		printk ("Kmalloc for obj failed!\n");
		return -ENOMEM;
	}
	
	for (i = 0; i < addr_num; i++){
		block[i].length = BM_TEST_SIZE * (i+1);

		addr[i] = (unsigned long)httc_kmalloc (block[i].length, GFP_KERNEL);

		memset((void *)addr[i],value,block[i].length);
		block[i].physical_addr =  tdd_get_phys_addr ((void*)addr[i]);
	}
	objLen =  strlen (obj) + 1;
	memcpy ((void*)objAddress, obj, objLen);

	ret = tcsk_boot_measure (stage, addr_num, block, tdd_get_phys_addr ((void*)objAddress), objLen, &tpcmRes);
	printk ("[tcsk_boot_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
	if (ret || tpcmRes)	ret = -1;

	for (i = 0; i < addr_num; i++){
		 kfree ((void*)addr[i]);
	}
	if(objAddress!=0) httc_kfree(objAddress);
	return ret;
}
int boot_measure_selftest_init(void){
	int r;
	if((r = boot_measure_selftest("OPRUN 1",1,1001,0xfa)))return r;
	if((r = boot_measure_selftest("OPRUN 2",2,1002,0xea)))return r;
	if((r = boot_measure_selftest("Kernel",3,1003,0xd1)))return r;
	if((r = boot_measure_selftest("initramfs",2,1004,0x12)))return r;
	if((r = boot_measure_selftest("/etc/init",1,1005,0x45)))return r;
	return 0;
}
void boot_measure_selftest_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init(boot_measure_selftest_init);
module_exit(boot_measure_selftest_exit);

