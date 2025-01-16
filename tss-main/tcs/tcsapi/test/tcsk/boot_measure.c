#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tdd.h"
#include "memdebug.h"
#include "kutils.h"
#include "tcs_tpcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_boot_measure test");

#define BM_BLOCK_LIMIT	50

static unsigned int addr_num;
static unsigned int length_num;
static unsigned int stage = -1; 
static char *obj = NULL; 
static unsigned long addr[BM_BLOCK_LIMIT] = {0};
static unsigned int length[BM_BLOCK_LIMIT] = {0};

static void usage (void)
{
	printk ("\n");
	printk (" Usage: insmod boot_measure.ko stage=STAGE obj=OBJ addr=ADDR1,ADDR2... length=LENGTH1,LENGTH2...\n");
	printk ("    eg. insmod boot_measure.ko stage=1000 obj=GRUB addr=0x80000000,0x80002000 length=0x1000,0x2000\n\n");
	printk ("Tips  : You can enter up to 50 groups of (addr, length)\n");
	printk ("\n");
}

int boot_measure_init(void)
{
	int i = 0;
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct physical_memory_block block[BM_BLOCK_LIMIT];
	uint8_t *objAddress = NULL;
	uint32_t objLen = 0;

	printk ("[%s:%d]\n", __func__, __LINE__);
	if ((NULL == obj) || (0 == addr_num) || (0 == length_num) || (-1 == stage)){
		usage ();
		return -EINVAL;
	}
	if (addr_num != length_num){
		printk ("Invalid Param: addr_num != length_num.\n\n");
		usage ();
		return -EINVAL;
	}
	if (addr_num > BM_BLOCK_LIMIT){
		printk ("Invalid Param: addr_num is to large.\n\n");
		usage ();
		return -EINVAL;
	}

	if (NULL == (objAddress = httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
		printk ("Kmalloc for obj failed!\n");
		return -ENOMEM;
	}
	
	for (i = 0; i < addr_num; i++){
		block[i].physical_addr = addr[i];
		block[i].length = length[i];
	}
	objLen =  strlen (obj) + 1;
	memcpy ((void*)objAddress, obj, objLen);
	      
	ret = tcsk_boot_measure (stage, addr_num, block, tdd_get_phys_addr (objAddress), objLen, &tpcmRes);
	printk ("[tcsk_boot_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
	if (ret || tpcmRes)	ret = -1;
	
	httc_kfree (objAddress);	
	return ret;
}

void boot_measure_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_param(stage, uint, S_IRUGO | S_IWUSR);
module_param(obj, charp, S_IRUGO | S_IWUSR);
module_param_array(addr, ulong, &addr_num, S_IRUGO | S_IWUSR);
module_param_array(length, uint, &length_num, S_IRUGO | S_IWUSR);


module_init(boot_measure_init);
module_exit(boot_measure_exit);

