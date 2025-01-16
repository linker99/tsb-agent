#include <linux/kernel.h>
#include <linux/module.h>

#include "tcsk_tcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_nv_write test");

static uint32_t index = 0;
static char *data = NULL;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod nv_write.ko index=INDEX data=DATE\n");
	printk ("    eg. insmod nv_write.ko index=1 data=1234567890\n");
	printk ("\n");
}


int test_nv_write_init(void)
{
	int ret = 0;

	if (!index || !data){
		usage ();
		return -1;
	}
	ret = tcsk_nv_write ((uint32_t)index, (uint8_t *)data, (uint32_t)(strlen (data) + 1));
	if(ret){
		printk ("Error: tcsk_nv_write fail! ret:0x%016x!\n", ret);
		return -1;
	}
	return 0;
}

void test_nv_write_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(data, charp, S_IRUGO | S_IWUSR);

module_init(test_nv_write_init);
module_exit(test_nv_write_exit);


