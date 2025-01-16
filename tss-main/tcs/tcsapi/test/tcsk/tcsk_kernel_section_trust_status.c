#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_kernel_section_trust_status test");

int tcsk_kernel_section_trust_status_init (void)
{
	int ret = 0;
	struct kernel_section_info kernel_section_para;
	kernel_section_para.measure_ret=0;
	memcpy(kernel_section_para.obj_name,"kernelsection",strlen("kernelsection"));
	memset(kernel_section_para.hash_data,0,32);
	ret = tcsk_kernel_section_trust_status(&kernel_section_para) ;

	if (ret ){	
		printk ("[%s:%d]ret: 0x%08x\n", __func__, __LINE__,kernel_section_para.measure_ret);

		return ret;
	}
	
	return 0;
}

void tcsk_kernel_section_trust_status_exit (void)
{
	return;
}


module_init(tcsk_kernel_section_trust_status_init);
module_exit(tcsk_kernel_section_trust_status_exit);

