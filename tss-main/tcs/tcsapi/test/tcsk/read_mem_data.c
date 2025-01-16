#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_read_mem_data test");

static uint32_t index = 0;
static char *usepasswd = NULL;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod read_mem_data.ko index=INDEX usepasswd=PASSWD1PASSWD2...PASSWDn\n");
	printk ("eg. insmod read_mem_data.ko index=1 usepasswd=12...n(8<=n<=32)\n");
	printk ("\n");
}

int test_read_mem_data(void)
{
	int ret = 0, i = 0;
	uint8_t data[128] = {0};
    uint32_t length_inout = sizeof(data);
/*
    uint32_t passwd_len = strlen(usepasswd);
	if (0 == index){
        usage();
		return -EINVAL;
    }
    if((passwd_len < 8) || (passwd_len > 32)){
		printk("[%s:%d] illegal passwd\n", __func__, __LINE__);
		usage ();
		return -EINVAL;
    }
*/
	if (usepasswd == NULL){
        usage();
		return -EINVAL;
	}

	printk("************test_read_mem_data ************\n");
	ret = tcsk_read_mem_data(index, (int *)&length_inout, (unsigned char *)data, usepasswd);
	if(ret) {
		printk("[%s:%d]ret: 0x%08x\n", __func__, __LINE__, ret);
		return -1;
	}

    for(i = 0;i < length_inout;i++)
    {
        printk("[%s:%d]save_mem_data[%d]:%08x\n",__func__, __LINE__, i, data[i]);
    }
	return 0;
}

int test_read_memdata_init(void)
{
	int ret = 0;

	if((ret = test_read_mem_data()) != 0) {
		printk("test_read_mem_data, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

void test_read_memdata_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(usepasswd, charp, S_IRUGO | S_IWUSR);

module_init(test_read_memdata_init);
module_exit(test_read_memdata_exit);


