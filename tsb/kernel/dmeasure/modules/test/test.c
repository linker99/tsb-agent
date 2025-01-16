#include <linux/module.h>

static int __init test_init(void)
{
	int ret = 0;

	printk("Test Init Success!\n");

	return ret;
}

static void __exit test_exit(void)
{
	printk("Test Exit Success!\n");
	return;
}

module_init(test_init);
module_exit(test_exit);

MODULE_AUTHOR("TEST");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TEST MODULE");
