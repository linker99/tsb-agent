#include <linux/kernel.h>
#include <linux/module.h>

#include "version.h"
#include "tcs_tpcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_set_system_time test");

int set_systemtime_init (void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval tv;
	httc_gettimeofday (&tv);
	ret = tcsk_set_system_time (tv.tv_sec, &tpcmRes);
	printk ("[%s:%d]ret: 0x%08x, tpcmRes: 0x%08x\n", __func__, __LINE__, ret, tpcmRes);
	if (ret || tpcmRes)	return -1;
	printk ("[%s:%d]tv_sec: 0x%08x\n", __func__, __LINE__, (unsigned int)tv.tv_sec);
	
	return 0;
}

void set_systemtime_exit (void)
{
	return;
}

module_init(set_systemtime_init);
module_exit(set_systemtime_exit);

