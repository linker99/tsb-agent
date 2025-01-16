#include <linux/kernel.h>
#include <linux/module.h>

#include "kutils.h"
#include "tcs_tpcm.h"
#include "tcs_constant.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_simple_boot_measure test");

static unsigned int stage = -1; 
static char *obj = NULL; 
static char *digest = NULL; 

static void usage (void)
{
	printk ("\n");
	printk (" Usage: insmod simple_boot_measure.ko stage=STAGE obj=OBJ digest=DIGEST\n");
	printk ("    eg. insmod simple_boot_measure.ko stage=1000 obj=GRUB digest=704730DC2D10D5C33C6B92808FEA00739DF291580A3530B109F97A8BD2B7309E\n");
	printk ("\n");
}

int simple_boot_measure_init(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint8_t  digestHex[DEFAULT_HASH_SIZE] = {0};

	printk ("[%s:%d]\n", __func__, __LINE__);
	
	if ((NULL == obj) || (0 == digest) || (-1 == stage)){
		usage ();
		return -EINVAL;
	}

	if (strlen (digest) != DEFAULT_HASH_SIZE*2){
		return -EINVAL;
	}

	httc_util_str2array (digestHex, (uint8_t *)digest, DEFAULT_HASH_SIZE*2);
	
	ret = tcsk_simple_boot_measure (stage, digestHex, (uint8_t *)obj, strlen (obj) + 1, &tpcmRes);
	printk ("[tcsk_simple_boot_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
	if (ret || tpcmRes)	ret = -1;

	return ret;
}

void simple_boot_measure_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_param(stage, uint, S_IRUGO | S_IWUSR);
module_param(obj, charp, S_IRUGO | S_IWUSR);
module_param(digest, charp, S_IRUGO | S_IWUSR);

module_init(simple_boot_measure_init);
module_exit(simple_boot_measure_exit);

