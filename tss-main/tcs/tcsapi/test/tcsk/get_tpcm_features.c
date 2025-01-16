#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_get_tpcm_features test");



int test_get_tpcm_features(void)
{
	int ret = 0;
	uint32_t feature;

	ret = tcsk_get_tpcm_features(&feature);
	if(ret) {
		printk("[tcsk_get_tpcm_features] ret: 0x%08x\n", ret);
		return -1;
	}
	
	printk("imeasure:%s\n", feature & 1 ? "YES":"NO");
	printk("dmeasure:%s\n", feature >> 1 & 1 ? "YES":"NO");
	printk("simple_boot:%s\n", feature >> 2 & 1 ? "YES":"NO");
	printk("bios_result:%s\n", feature >> 3 & 1 ? "YES":"NO");
	printk("support_upgrade:%s\n", feature >> 4 & 1 ? "YES":"NO");
	printk("flash_access:%s\n", feature >> 5 & 1 ? "YES":"NO");
	printk("simple imeasure: %s\n", feature >> 6 & 1 ? "YES":"NO");

	return 0;
}

int test_get_tpcmfeatures_init(void)
{
	int ret = 0;

	if((ret = test_get_tpcm_features()) != 0) {
		printk("test_get_tpcm_features, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

void test_get_tpcmfeatures_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}


module_init(test_get_tpcmfeatures_init);
module_exit(test_get_tpcmfeatures_exit);



