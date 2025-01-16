#include <linux/kernel.h>
#include <linux/module.h>

#include "tcsk_tcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_nv_definespace test");

static uint32_t index = 0;
static int size = 0;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod nv_is_definespace.ko index=INDEX size=SIZE\n");
	printk ("    eg. insmod nv_is_definespace.ko index=1 size=1000\n");
	printk ("\n");
}

int test_nv_is_definespace_init(void)
{
	int ret = 0;

	if (!index || !size){
		usage ();
		return -1;
	}
	ret = tcsk_nv_is_definespace(index, size);
	if(ret){
		printk ("Error: tcsk_nv_is_definespace fail! ret:0x%016x!\n", ret);
		return -1;
	}


	return 0;
}

void test_nv_is_definespace_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(size, int, S_IRUGO | S_IWUSR);

module_init(test_nv_is_definespace_init);
module_exit(test_nv_is_definespace_exit);


