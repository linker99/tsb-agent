#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"
#include "tcs_license_def.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_get_license_status test");

const char * license_desc[LICENSE_ATTR_MAX] = {"ALL", "TPCM", "TSB", "TERM", "RESERVED"};
const char * license_type_desc[LICENSE_LTYPE_MAX] = {"V2.0", "V2.1"};
uint32_t license_type = LICENSE_ATTR_TPCM;

int get_license_info_init(void)
{
	int ret = 0;
	int status = 0;
	uint64_t deadline = 0;
    uint32_t be_license_type = 0;
    uint32_t be_license_type_low = 0;
    uint32_t be_license_type_high = 0;

	if(0 != (ret = tcsk_get_license_info (&status, &deadline))) {
		printk ("tcsk_get_license_info ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printk ("License status \n");
	printk ("status: %d\n", status);
	be_license_type = status;
	be_license_type_low = be_license_type & 0x0000ffff;
	be_license_type_high = (be_license_type & 0xffff0000) >> 16;
	printk("license_type    : %d, license_type_low    : %d, license_type_high    : %d\n", be_license_type, be_license_type_low, be_license_type_high);
	if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
		printk("version    : %s\n", license_type_desc[be_license_type_high]);
	}
	else
	{
		printk ("Invalid version : %d\n", be_license_type_high);
	}
	printk ("deadline  : %llu\n", deadline);
	printk ("\n");

	return 0;
}

void get_license_info_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init(get_license_info_init);
module_exit(get_license_info_exit);


