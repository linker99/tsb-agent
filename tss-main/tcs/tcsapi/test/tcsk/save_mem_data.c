#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_save_mem_data test");

static uint32_t index = 0;
static char *data = NULL;
static char *usepasswd = NULL;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod save_mem_data.ko index=INDEX data=DATA1DATA2...DATA usepasswd=PASSWD1PASSWD2...PASSWDn\n");
	printk ("eg. insmod save_mem_data.ko index=1 data=123.... usepasswd=12...n(8<=n<=32)\n");
	printk ("\n");
}

int test_save_mem_data(void)
{
	int ret = 0;
    uint32_t length = 0;
/*
    uint32_t passwd_len = strlen(usepasswd);
    if((passwd_len < 8) || (passwd_len > 32)){
		printk("[%s:%d] illegal passwd\n", __func__, __LINE__);
		usage ();
		return -EINVAL;
    }
*/
	if ((data == NULL) || (usepasswd == NULL)){
		usage ();
		return -EINVAL;
	}
	length = strlen(data);
	printk("************test_save_mem_data ************\n");
	ret = tcsk_save_mem_data(index, length, (unsigned char *)data, usepasswd);
	if(ret) {
		printk("[%s:%d]ret: 0x%08x\n", __func__, __LINE__, ret);
		return -1;
	}
	
	return 0;
}


int test_save_memdata_init(void)
{
	int ret = 0;

	if((ret = test_save_mem_data()) != 0) {
		printk("test_save_mem_data, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

void test_save_memdata_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(usepasswd, charp, S_IRUGO | S_IWUSR);
module_param(data, charp, S_IRUGO | S_IWUSR);

module_init(test_save_memdata_init);
module_exit(test_save_memdata_exit);



