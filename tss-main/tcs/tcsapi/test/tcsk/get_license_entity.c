#include <linux/kernel.h>
#include <linux/module.h>

#include "tcs_kernel.h"
#include "tcs_license_def.h"

#include "debug.h"
//#include "memdebug.h"
//#include "kutils.h"
//#include "tdd.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_get_license_entity test");

const char * license_desc[LICENSE_ATTR_MAX] = {"ALL", "TPCM", "TSB", "TERM", "RESERVED"};
const char * license_type_desc[LICENSE_LTYPE_MAX] = {"V2.0", "V2.1"};
uint32_t license_type = LICENSE_ATTR_ALL;

int get_license_entity_init(void)
{
	int ret = 0;
    struct license_entity data[4];
    int num = 0;
    uint32_t be_license_type = 0;
    uint32_t be_license_type_low = 0;
    uint32_t be_license_type_high = 0;
	int i = 0;

    memset(data, 0, sizeof(data));
    if(0 != (ret = tcsk_get_license_entity (data, &num))) {
        printk ("tcsk_get_license_entity ret: %d(0x%08x)\n", ret, ret);
        return -1;
    }

    printk("license_entity, num is : %d\n", num);
    for (i = 0; i < num; ++i)
    {
        be_license_type = ntohl(data[i].be_license_type);
        be_license_type_low = be_license_type & 0x0000ffff;
        be_license_type_high = (be_license_type & 0xffff0000) >> 16;
        printk ("\n");
        printk("license_entity, i is : %d\n", i);
        printk("license_type    : %d, license_type_low    : %d, license_type_high    : %d\n", be_license_type, be_license_type_low, be_license_type_high);
        if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
            printk("version    : %s\n", license_type_desc[be_license_type_high]);
        }
        printk("client_id_length    : %d\n", ntohl(data[i].be_client_id_length));
        printk("tpcm_id_length    : %d\n", ntohl(data[i].be_tpcm_id_length));
        printk("host_id_length    : %d\n", ntohl(data[i].be_host_id_length));
        printk ("time_stamp    : %llu\n", data[i].be_time_stamp);
        printk ("deadline    : %llu\n", data[i].be_deadline);

        httc_util_dump_hex ("client_id", data[i].client_id, ntohl(data[i].be_client_id_length));
        httc_util_dump_hex ("tpcm_id", data[i].tpcm_id, ntohl(data[i].be_tpcm_id_length));
        httc_util_dump_hex ("host_id", data[i].host_id, ntohl(data[i].be_host_id_length));
        printk ("\n");
    }

    return 0;
}

void get_license_entity_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init(get_license_entity_init);
module_exit(get_license_entity_exit);


