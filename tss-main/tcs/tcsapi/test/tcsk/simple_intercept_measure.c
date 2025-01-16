#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>

#include "memdebug.h"
#include "kutils.h"
#include "version.h"
#include "tdd.h"
#include "tcs_tpcm.h"
#include "tcs_kernel.h"
#include "tcs_constant.h"
#include "sm3.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("simple_intercept_memasure test");

#ifndef RATE_CHECK
#define RATE_CHECK
//#undef RATE_CHECK
#endif

#define IM_SIZE (PAGE_SIZE * 16)

static char *imname = NULL;
static unsigned int imtype = 0;

void Usage (void)
{
		printk ("\n");
		printk (" Usage: insmod simple_intercept_measure.ko imname=NAME imtype=TYPEID\n");
		printk ("  		 -imname:	Intercept measure filename\n");
		printk ("  		 -imtype:	Intercept measure type\n");
		printk ("  		 		    1 - IMT_PROCESS_EXEC\n");
		printk ("  		 		    2 - IMT_DYNAMIC_LIBRARY_LOAD\n");
		printk ("  		 		    3 - IMT_KERNEL_MODULE_LOAD\n");
		printk ("    eg. insmod simple_intercept_measure.ko imname=/usr/bin/gdb imtype=1\n\n");
}

static int  simple_intercept_memasure_init(void)
{	
	int ret = 0;
	uint32_t tpcmRes = 0;
	ssize_t  imSize = 0;
	uint8_t *name = NULL;
	uint32_t name_length = 0;
	uint32_t path_len = 0;
	uint8_t *path_addr = NULL;
	struct file *fp = NULL;
	unsigned int imfileSize = 0;
	sm3_context ctx;
	uint8_t hash[DEFAULT_HASH_SIZE] = {0};
	void *imfileData = NULL;

#ifdef RATE_CHECK
	struct timeval tv_start;
	struct timeval tv_end;
	int in_sec;		/* Seconds. */
	int in_usec;	/* Microseconds. */
#endif

	if ((NULL == imname) || (0 == imtype)){
		Usage ();
		return -1;
	}

	if (NULL == (path_addr = (uint8_t *)httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
		printk ("[%s:%d] Malloc path_addr error\n", __func__, __LINE__);
		return -ENOMEM;
	}

    fp = filp_open(imname, O_RDONLY, 0);
    if (IS_ERR(fp)) {
            printk("error occured while opening file %s, exiting...\n", imname);
			ret = -PTR_ERR(fp);
			goto out;
    }
    imfileSize = tpcm_file_size (fp);

	if (NULL == (imfileData = (uint8_t *)httc_vmalloc (imfileSize))){
		printk ("[%s:%d] Malloc imfileData error\n", __func__, __LINE__);
		return -ENOMEM;
	}

	imSize = tpcm_kernel_read (fp, imfileData, imfileSize, &fp->f_pos);
	if (imSize != imfileSize){
		printk ("[%s:%d]read %s error!\n", __func__, __LINE__, imname);
		ret = -1;
		goto out;
	}

	httc_sm3_init (&ctx);
	httc_sm3_update (&ctx, (const unsigned char *)imfileData, imfileSize);
	httc_sm3_finish (&ctx, hash);


	name = (uint8_t *)(strrchr ((const char *)imname, '/') + 1);
	name_length = strlen ((const char *)name) + 1;
	path_len = strlen (imname) - name_length + 1;
	memcpy (path_addr, imname, path_len);
	tpcm_util_cache_flush (path_addr, path_len);

#ifdef RATE_CHECK
	httc_gettimeofday (&tv_start);
	ret = tcsk_integrity_measure_simple (
		path_len, path_addr, imtype, DEFAULT_HASH_SIZE, hash, &tpcmRes);
	httc_gettimeofday (&tv_end);
	printk ("[tcsk_integrity_measure_simple]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
	in_sec = (tv_end.tv_usec - tv_start.tv_usec >= 0) ? (tv_end.tv_sec - tv_start.tv_sec) : (tv_end.tv_sec - tv_start.tv_sec - 1);
	in_usec = (tv_end.tv_usec - tv_start.tv_usec >= 0) ? (tv_end.tv_usec - tv_start.tv_usec) : (tv_end.tv_usec - tv_start.tv_usec + 1000000);

	if (imfileSize / 1024 / 1024){
		printk (">>> Intercept: filename(%s), size(%d.%03dMB), time(%d.%06ds) <<<\n",
				imname, imfileSize / 1024 / 1024, imfileSize / 1024 % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else if (imfileSize / 1024){
		printk (">>> Intercept: filename(%s), size(%d.%03dKB), time(%d.%06ds) <<<\n",
				imname, imfileSize / 1024, imfileSize % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else{
		printk (">>> Intercept: filename(%s), size(%dB), time(%d.%06ds) <<<\n", imname, imfileSize, in_sec, in_usec);
	}
#else
	ret = tcsk_integrity_measure_simple (
		path_len, path_addr, imtype, DEFAULT_HASH_SIZE, hash, &tpcmRes);
	printk ("[tcsk_integrity_measure_simple]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
#endif

out:
	if (IS_ERR (fp))	filp_close(fp, NULL);
	if (imfileData) httc_vfree (imfileData);
	if (path_addr) httc_kfree (path_addr);
	return ret;
}

void simple_intercept_memasure_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_param(imname, charp,  S_IRUGO | S_IWUSR);
module_param(imtype, uint, S_IRUGO | S_IWUSR);

module_init(simple_intercept_memasure_init);
module_exit(simple_intercept_memasure_exit);


