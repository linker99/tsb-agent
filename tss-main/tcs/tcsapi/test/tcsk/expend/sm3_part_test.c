#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>


#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_tcm.h"
#include "tcs_constant.h"
#include "tcsk_sm.h"
#include "smk/sm3.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_sm3 test");

static uint size = 0;
static char *data = NULL;

static void usage (void)
{
	printk ("\n");
	printk (" Usage: insmod sm3_test.ko size=SIZE | data=DATA \n");
	printk ("    eg. insmod sm3_test.ko size=0x1000\n");
	printk ("    eg. insmod sm3_test.ko data=helloworld\n");
	printk ("\n");
}

int sm3_test_init(void)
{
	int ret = 0;
	int olen = DEFAULT_HASH_SIZE;
	uint8_t output[DEFAULT_HASH_SIZE];
	uint8_t output_except[DEFAULT_HASH_SIZE];
	uint8_t *input;
	uint32_t reseLen = 0;
	uint32_t curLen = 0;
	uint32_t opt = 0;
	void* ctx = NULL;
	
	httc_util_pr_dev ("[%s:%d] size: 0x%x, data: %s\n", __func__, __LINE__, size, data);

	if (!size && !data){
		usage ();
		return -1;
	}

	if (size){
		if (NULL == (input = httc_vmalloc (size))){
			httc_util_pr_error ("Nomem!\n");
			return -1;
		}
		memset (input, 0x12, size);

		if (0 != (ret = tcsk_sm3_init (&ctx))){
			httc_util_pr_error ("tcs_sm3_init error: %d\n", ret);
			httc_vfree (input);
			return -1;
		}

		reseLen = size;
		do {
			curLen = MIN(reseLen, SM3_UPDATE_SIZE_LIMIT);	
			if (0 != (ret = tcsk_sm3_update (ctx, input+opt, curLen))){
				httc_util_pr_error ("tcs_sm3_update error: %d\n", ret);
				httc_vfree (input);
				return -1;
			}
			opt += curLen;
			reseLen -= curLen;
		}while (reseLen);

		if (0 != (ret = tcsk_sm3_finish (ctx, output))){
			httc_util_pr_error ("tcs_sm3_finish error: %d\n", ret);
			httc_vfree (input);
			return -1;
		}

		httc_sm3 (input, size, output_except);
		if (memcmp (output, output_except, DEFAULT_HASH_SIZE)){
			httc_util_pr_error ("Incorrect digest result!\n");
			httc_util_dump_hex ("output", (void *)output, olen);
			httc_util_dump_hex ("output_except", (void *)output_except, DEFAULT_HASH_SIZE);
			httc_vfree (input);
			return -1;
		}
		httc_util_dump_hex ("output", (void *)output, olen);
		httc_vfree (input);
		return 0;
	}
	if (data){
		if (0 != (ret = tcsk_sm3_init (&ctx))){
			httc_util_pr_error ("tcs_sm3_init error: %d\n", ret);
			return -1;
		}

		if (0 != (ret = tcsk_sm3_update (ctx, (uint8_t *)data, strlen(data)))){
			httc_util_pr_error ("tcs_sm3_update error: %d\n", ret);
			return -1;
		}
		
		if (0 != (ret = tcsk_sm3_finish (ctx, output))){
			httc_util_pr_error ("tcs_sm3_finish error: %d\n", ret);
			return -1;
		}
   
		httc_sm3 ((const unsigned char *)data, (int)strlen (data), (unsigned char *)output_except);
		if (memcmp (output, output_except, DEFAULT_HASH_SIZE)){
			httc_util_pr_error ("Incorrect digest result!\n");
			httc_util_dump_hex ("output", (void *)output, olen);
			httc_util_dump_hex ("output_except", (void *)output_except, DEFAULT_HASH_SIZE);
			return -1;
		}
		httc_util_dump_hex ("output", (void *)output, olen);
		return 0;
	}
	return 0;
}

void sm3_test_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}


module_param(size, uint, S_IRUGO | S_IWUSR);
module_param(data, charp, S_IRUGO | S_IWUSR);


module_init(sm3_test_init);
module_exit(sm3_test_exit);


