#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "version.h"
#include "sm3.h"
#include "tdd.h"
#include "tcs_kernel.h"
#include "tcs_kernel_def.h"
#include "tcs_constant.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("TPCM_InterceptMeasure test");

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
		printk (" Usage: insmod intercept_measure.ko imname=NAME imtype=TYPEID\n");
		printk ("  		 -imname:	Intercept measure filename\n");
		printk ("  		 -imtype:	Intercept measure type\n");
		printk ("  		 		    1 - IMT_PROCESS_EXEC\n");
		printk ("  		 		    2 - IMT_DYNAMIC_LIBRARY_LOAD\n");
		printk ("  		 		    3 - IMT_KERNEL_MODULE_LOAD\n");
		printk ("    eg. insmod intercept_measure.ko imname=/usr/bin/gdb imtype=1\n\n");
}

static int  intercept_memasure_init(void)
{	
	int ret = 0;
	uint32_t tpcmRes = 0;
	ssize_t  imSize = 0;
	uint32_t path_len = 0;
	uint8_t *path_addr = NULL;
	uint32_t blockNum = 0;
	struct physical_memory_block *block = NULL;
	struct physical_memory_block *virblock = NULL;
	uint32_t mrLen = 32;
	uint8_t mresult[32] = {0};
	struct file *fp = NULL;
	unsigned int imfileSize = 0;
	unsigned int imLengthOnce = 0;
	unsigned int imUserLengthRest = 0;
	unsigned int imLengthOpt = 0;
	unsigned int blockSize = 0;
	sm3_context ctx;
	uint8_t hash[DEFAULT_HASH_SIZE] = {0};


#ifdef RATE_CHECK
	struct timeval tv_start;
	struct timeval tv_end;
	int in_sec;		/* Seconds. */
	int in_usec;	/* Microseconds. */
#endif
	
	if ((NULL == imname) || (0 == imtype)){
		Usage ();
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
	blockSize = sizeof (struct physical_memory_block) * (imfileSize / IM_SIZE + 1);

	if (NULL == (block = (struct physical_memory_block *)httc_vmalloc (blockSize))){
		printk ("[%s:%d] Malloc block error\n", __func__, __LINE__);
		httc_kfree (path_addr);
		filp_close(fp, NULL);
		return -ENOMEM;
	}	
	if (NULL == (virblock = (struct physical_memory_block *)httc_vmalloc (blockSize))){
		printk ("[%s:%d] Malloc virblock error\n", __func__, __LINE__);
		httc_kfree (path_addr);
		httc_kfree (block);
		filp_close(fp, NULL);
		return -ENOMEM;
	}

	httc_sm3_init (&ctx);
	imUserLengthRest = imfileSize;
	do {
		imLengthOnce = (imUserLengthRest < IM_SIZE) ? imUserLengthRest : IM_SIZE;

		if (0 == (virblock[blockNum].physical_addr = (unsigned long)httc_kzalloc (IM_SIZE, GFP_KERNEL)))	{

			printk ("[%s:%d]Kmalloc block[%d] error!\n", __func__, __LINE__, blockNum);
			ret = -ENOMEM;
			goto out;
		}

		imSize = tpcm_kernel_read (fp, (char *)(unsigned long)(virblock[blockNum].physical_addr), imLengthOnce, &fp->f_pos);
		if (imSize != imLengthOnce){
			printk ("[%s:%d]read %s error!\n", __func__, __LINE__, imname);
			return -1;
			goto out;
		}
		httc_sm3_update (&ctx, (const unsigned char *)(unsigned long)(virblock[blockNum].physical_addr), imLengthOnce);
		tpcm_util_cache_flush ((void*)(unsigned long)(virblock[blockNum].physical_addr), imLengthOnce);
		block[blockNum].physical_addr = tdd_get_phys_addr((void*)(unsigned long)virblock[blockNum].physical_addr);
		block[blockNum].length = imLengthOnce;
		blockNum ++;
		imLengthOpt += imLengthOnce;
		imUserLengthRest -= imLengthOnce;
	}while (imUserLengthRest);
	httc_sm3_finish (&ctx, hash);

	path_len = strlen (imname) + 1;
	memcpy (path_addr, imname, path_len);
	path_addr[path_len - 1] = '\0';
	tpcm_util_cache_flush (path_addr, path_len);

#ifdef RATE_CHECK
	httc_gettimeofday (&tv_start);
	ret = tcsk_integrity_measure (path_len, path_addr, imtype, blockNum, block, &tpcmRes, &mrLen, mresult);
	httc_gettimeofday (&tv_end);
	printk ("[tcsk_integrity_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
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
	ret = tcsk_integrity_measure (path_len, path_addr, imtype, blockNum, block, &tpcmRes, &mrLen, mresult);
	printk ("[tcsk_integrity_measure]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
#endif

	if ((0 == ret) && (0 != mrLen)){
		httc_util_dump_hex ("mresult", mresult, mrLen);
		httc_util_dump_hex ("Calc Hash", hash, DEFAULT_HASH_SIZE);
	}
	if (ret || (tpcmRes >> 16))	ret = -1;

out:
	if (fp)	filp_close(fp, NULL);
	if (block) httc_vfree (block);
	while (blockNum--)	if (virblock[blockNum].physical_addr) httc_kfree ((void*)(unsigned long)virblock[blockNum].physical_addr);
	if (virblock) httc_vfree (virblock);
	if (path_addr) httc_kfree (path_addr);
	return ret;
}

void intercept_memasure_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}

module_param(imname, charp,  S_IRUGO | S_IWUSR);
module_param(imtype, uint, S_IRUGO | S_IWUSR);

module_init(intercept_memasure_init);
module_exit(intercept_memasure_exit);

