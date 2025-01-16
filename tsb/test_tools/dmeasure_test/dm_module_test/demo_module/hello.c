#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "debug.h"


#define DEVICE_NAME "HelloModule"


static int __init hello_init(void)
{
	printk("## %s \n", __func__);
  pdrive_print(PDRIVE_ERR, INTERCEPT, "%s ERR INTERCEPT initialized.\n", DEVICE_NAME);
	pdrive_print(PDRIVE_WARNING, ENGINE, "%s WARNING ENGINE initialized.\n", DEVICE_NAME);
	pdrive_print(PDRIVE_NOTICE, MEASURE, "%s NOTICE MEASURE initialized.\n", DEVICE_NAME);
	pdrive_print(PDRIVE_INFO, INTERCEPT, "%s INFO INTERCEPT initialized.\n", DEVICE_NAME);
	pdrive_print(PDRIVE_DEBUG, MEASURE, "%s DEBUG MEASURE initialized.\n", DEVICE_NAME);
//	print_message(PDRIVE_DEBUG, MEASURE, "%s DEBUG MEASURE initialized.\n", DEVICE_NAME);
    
    return 0;
}

static void __exit hello_exit(void)
{
	printk("##### %s -- \n", __func__);
  pdrive_print(PDRIVE_NOTICE, MEASURE, DEVICE_NAME "NOTICE, MEASURE, removed.\n");
	pdrive_print(PDRIVE_INFO, INTERCEPT, DEVICE_NAME "INFO, INTERCEPT, removed.\n");
	pdrive_print(PDRIVE_WARNING, ENGINE, DEVICE_NAME "WARNING, ENGINE, removed.\n");
	pdrive_print(PDRIVE_INFO, MEASURE, DEVICE_NAME "INFO, MEASURE, removed.\n");
	pdrive_print(PDRIVE_WARNING, ENGINE, DEVICE_NAME "WARNING, ENGINE, removed.\n");
}

module_param_named(level, default_level, int, S_IRUGO);
module_param_named(type, default_type, int, S_IRUGO);

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
