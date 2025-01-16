#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tcsk_tcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_nv_read test");

static uint32_t index = 0;
static int size = 0;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod nv_read.ko index=INDEX size=SIZE\n");
	printk ("    eg. insmod nv_read.ko index=1 size=10\n");
	printk ("\n");
}

int test_nv_read_init(void)
{
	int ret = 0;
	char *data = NULL;

	if (!index || !size){
		usage ();
		return -1;
	}
	
	if (NULL == (data = kmalloc (size+1, GFP_KERNEL))){
		printk ("Kmallc mem error.\n");
		return -1;
	}
	memset (data, 0, size + 1);
 
	ret = tcsk_nv_read ((uint32_t)index, (uint8_t*)data, (uint32_t *)(&size));
	if(ret){
		printk ("Error: tcsk_nv_read fail! ret:0x%016x!\n", ret);
		kfree (data);
		return -1;
	}
	printk ("Nv data: %s\n", data);
	kfree (data);
	return 0;
}

void test_nv_read_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(size, int, S_IRUGO | S_IWUSR);

module_init(test_nv_read_init);
module_exit(test_nv_read_exit);


