#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_get_trust_status test");



int test_get_trust_status(void)
{
	int ret = 0;
	uint32_t status;

	if((ret = tcsk_get_trust_status(&status)) == 0) {
		printk("[tcsk_get_trust_status] Trusted status: %d\n", status);
	}
	else {
		printk("[tcsk_get_trust_status] ret: 0x%08x\n", ret);
		return -1;
	}

	return 0;
}

int test_get_trust_status_init(void)
{
	int ret = 0;

	if((ret = test_get_trust_status()) != 0) {
		printk("test_get_trust_status, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

void test_get_trust_status_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}


module_init(test_get_trust_status_init);
module_exit(test_get_trust_status_exit);




