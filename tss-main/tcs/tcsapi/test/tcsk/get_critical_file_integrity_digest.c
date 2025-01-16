#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "debug.h"
#include "tcs_kernel.h"

static int   get_critical_file_integrity_digest_init(void)
{
	int ret = 0;
	unsigned char digest[32] = {0};
	unsigned int digest_len = 32;

	printk("get_critical_file_integrity_digest_init\n");
	ret = tcsk_get_critical_file_integrity_digest (digest , &digest_len);
	if(ret)
	{
		printk(" tcsk get critical file integrity digest error\n");
		return -1 ;
	}
	httc_util_dump_hex("tcsk integrity digest", digest, digest_len);

	return ret;
}

static void   get_critical_file_integrity_digest_exit(void)
{
	printk("get_critical_file_integrity_digest_exit\n");
}

module_init(get_critical_file_integrity_digest_init);
module_exit(get_critical_file_integrity_digest_exit);
MODULE_LICENSE("GPL");
