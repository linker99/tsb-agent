#include <linux/kernel.h>
#include <linux/module.h>
#include "flush_dcache.h"
#include "version.h"
#include "utils/debug.h"
/**
 * Flush dcache for tpcm
 **/
static unsigned long k_flush_area = INVALID_DATA_FULL_FF;
module_param(k_flush_area, ulong, 0644);
MODULE_PARM_DESC(k_flush_area, "ulong flush_area address");
void (*kernel_flush_area) (void *addr, size_t len);

int init_flush_dcache_area(void)
{
	int ret = 0;

	if (k_flush_area == 0xffffffffffffffff || k_flush_area == 0) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], init error! flush_area:[%lx]\n", __func__, k_flush_area);
		//return -EACCES;
	} else {
		DEBUG_MSG(HTTC_TSB_DEBUG,"Enter:[%s], flush_area:[%lx] init success!\n", __func__, k_flush_area);
	}

	kernel_flush_area = (void *)k_flush_area;

	return ret;
}

void kernel_flush_dcache_area(void *addr, size_t len)
{
	if (k_flush_area == 0xffffffffffffffff || k_flush_area == 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], error! flush_area:[%lx]\n", __func__, k_flush_area);
		return;
	}
	kernel_flush_area(addr, len);
}


