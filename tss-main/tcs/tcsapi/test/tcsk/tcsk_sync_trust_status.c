#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_sync_trust_status test");

int tcsk_sync_trust_status_init (void)
{
	int ret = 0;
	uint32_t type = 1;
	ret = tcsk_sync_trust_status(type) ;
	if (ret ){	
		printk ("[%s:%d]type: 0x%08x\n", __func__, __LINE__, type);
		return ret;
	}
	return 0;
}

void tcsk_sync_trust_status_exit (void)
{
	return;
}

module_init(tcsk_sync_trust_status_init);
module_exit(tcsk_sync_trust_status_exit);

