#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_tpcm.h"
#include "sm3.h"
#include "tdd.h"
#include "tcs_tpcm_error.h"
#include "tcs_constant.h"
#include "tcs_attest_def.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_extern_simple_boot_meausre test");

extern int tcs_extern_simple_boot_meausre (
		uint32_t pcr, uint32_t stage, uint8_t *digest, uint8_t *obj, uint32_t objLen, uint32_t *tpcmRes);



#define BM_BLOCK_LIMIT	20
#define BM_TEST_SIZE	0x1000

struct bmeasure_extern_pcr{
	uint8_t bios_pcr[DEFAULT_HASH_SIZE];
	uint8_t grub_pcr[DEFAULT_HASH_SIZE];
	uint8_t kernel_pcr[DEFAULT_HASH_SIZE];
	uint8_t tsb_pcr[DEFAULT_HASH_SIZE];
	uint8_t boot_pcr[DEFAULT_HASH_SIZE];
};

struct bmeasure_extern_pcr bmeasure_pcr;

static int extern_simple_bmeasure_test(uint32_t pcr, char *obj,int addr_num,int stage,int value)
{
	int i = 0;
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint8_t *objAddress = NULL;
	uint32_t objLen = 0;
	sm3_context ctx;
	unsigned long addr[BM_BLOCK_LIMIT] = {0};
	struct physical_memory_block block[BM_BLOCK_LIMIT];
	uint8_t digest[DEFAULT_HASH_SIZE] = {0};

	if (addr_num > BM_BLOCK_LIMIT){
		printk ("Invalid Param: addr_num != length_num.\n\n");
		return -EINVAL;
	}

	if (NULL == (objAddress = httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
		printk ("Kmalloc for obj failed!\n");
		return -ENOMEM;
	}

	httc_sm3_init (&ctx);
	for (i = 0; i < addr_num; i++){
		block[i].length = BM_TEST_SIZE * (i+1);

		addr[i] = (unsigned long)httc_kmalloc (block[i].length, GFP_KERNEL);

		memset((void *)addr[i],value,block[i].length);
		block[i].physical_addr =  tdd_get_phys_addr ((void*)addr[i]);
		httc_sm3_update (&ctx, (const uint8_t *)addr[i], block[i].length);
	}
	httc_sm3_finish (&ctx, digest);

	objLen =  strlen (obj) + 1;
	memcpy ((void*)objAddress, obj, objLen);

//	ret = tcs_extern_simple_boot_meausre (pcr, stage, digest, (uint8_t *)tdd_get_phys_addr ((void*)objAddress), objLen, &tpcmRes);
	ret = tcs_extern_simple_boot_meausre (pcr, stage, digest, objAddress, objLen, &tpcmRes);

	printk ("[tcs_extern_simple_boot_meausre]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);

	if (((tpcmRes & 0xFF) == 0) || ((tpcmRes >> 16) == TPCM_MEASURE_FAIL)){
			switch (pcr){
				case BOOT_PCR_BIOS:
					httc_sm3_init (&ctx);
					httc_sm3_update (&ctx, bmeasure_pcr.bios_pcr, DEFAULT_HASH_SIZE);
					httc_sm3_update (&ctx, digest, DEFAULT_HASH_SIZE);
					httc_sm3_finish (&ctx, bmeasure_pcr.bios_pcr);
				case BOOT_PCR_BOOTLOADER:
					httc_sm3_init (&ctx);
					httc_sm3_update (&ctx, bmeasure_pcr.grub_pcr, DEFAULT_HASH_SIZE);
					httc_sm3_update (&ctx, digest, DEFAULT_HASH_SIZE);
					httc_sm3_finish (&ctx, bmeasure_pcr.grub_pcr);
				case BOOT_PCR_KERNEL:
					httc_sm3_init (&ctx);
					httc_sm3_update (&ctx, bmeasure_pcr.kernel_pcr, DEFAULT_HASH_SIZE);
					httc_sm3_update (&ctx, digest, DEFAULT_HASH_SIZE);
					httc_sm3_finish (&ctx, bmeasure_pcr.kernel_pcr);
				case BOOT_PCR_TSB:
					httc_sm3_init (&ctx);
					httc_sm3_update (&ctx, bmeasure_pcr.tsb_pcr, DEFAULT_HASH_SIZE);
					httc_sm3_update (&ctx, digest, DEFAULT_HASH_SIZE);
					httc_sm3_finish (&ctx, bmeasure_pcr.tsb_pcr);
				default:
					break;
			}
	}else{
		ret = -1;
	}

	for (i = 0; i < addr_num; i++){
		 httc_kfree ((void*)addr[i]);
	}
	if(objAddress!=0) httc_kfree(objAddress);
	return ret;
}

int extern_simple_bmeasure_selftest_init (void)
{
	int r;
	if((r = extern_simple_bmeasure_test(0, "BIOSAPP 1/3", 1, 10, 0x10)))goto out;
	if((r = extern_simple_bmeasure_test(1, "BIOSAPP 2/3", 2, 11, 0x11)))goto out;
	if((r = extern_simple_bmeasure_test(1, "BIOSAPP 2/3", 3, 12, 0x12)))goto out;
	if((r = extern_simple_bmeasure_test(2, "GRUB 1/3", 1, 1000, 0x1000)))goto out;
	if((r = extern_simple_bmeasure_test(0, "GRUB 2/3", 2, 1001, 0x1001)))goto out;
	if((r = extern_simple_bmeasure_test(2, "GRUB 1/3", 3, 1002, 0x1002)))goto out;
	if((r = extern_simple_bmeasure_test(3, "Kernel 1/3", 1, 2000, 0x2000)))goto out;
	if((r = extern_simple_bmeasure_test(3, "Kernel 2/3", 2, 2001, 0x2001)))goto out;
	if((r = extern_simple_bmeasure_test(0, "Kernel 3/3", 3, 2002, 0x2002)))goto out;

out:
	memcpy (bmeasure_pcr.boot_pcr, bmeasure_pcr.tsb_pcr, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("bios_pcr", bmeasure_pcr.bios_pcr, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("grub_pcr", bmeasure_pcr.grub_pcr, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("kernel_pcr", bmeasure_pcr.kernel_pcr, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("tsb_pcr", bmeasure_pcr.tsb_pcr, DEFAULT_HASH_SIZE);
	httc_util_dump_hex ("boot_pcr", bmeasure_pcr.boot_pcr, DEFAULT_HASH_SIZE);
	return r;
}

void extern_simple_bmeasure_selftest_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_init(extern_simple_bmeasure_selftest_init);
module_exit(extern_simple_bmeasure_selftest_exit);

