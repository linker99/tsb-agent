#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"
#include "debug.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_get_file_integrity_digest test");



int test_tcsk_get_file_integrity_digest(void)
{
	int ret = 0;
	int i = 0;
	uint8_t digest[32] = {0};
	uint32_t length = 32;
	
	ret = tcsk_get_file_integrity_digest((unsigned char *)digest,&length);
	if(ret) {
		printk("[tcsk_get_file_integrity_digest] ret: 0x%08x\n", ret);
		return -1;
	}
	for(;i < length;i++){
		printk("%x",digest[i]);
	}

	return 0;
}

int test_tcsk_get_file_integrity_digest_init(void)
{
	int ret = 0;

	if((ret = test_tcsk_get_file_integrity_digest()) != 0) {
		printk("test_tcsk_get_file_integrity_digest, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

void test_tcsk_get_file_integrity_digest_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}


module_init(test_tcsk_get_file_integrity_digest_init);
module_exit(test_tcsk_get_file_integrity_digest_exit);



