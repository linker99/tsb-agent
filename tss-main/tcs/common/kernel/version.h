#ifndef __VERSION_H__
#define __VERSION_H__

#ifdef __KERNEL__

#include <linux/version.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "tcs_attest_def.h"

#include <linux/timekeeping.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0))
	#define tpcm_file_size(fp) ((fp)->f_mapping->host->i_size)
#else
	#define tpcm_file_size(fp) ((fp)->f_inode->i_size)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0))
	#define tpcm_file_node(fp) ((fp)->f_dentry->d_inode)
#else
	#define tpcm_file_node(fp) ((fp)->f_inode)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline  ssize_t tpcm_kernel_write(struct file *file, const void *buf, size_t count,
			    loff_t *pos)
{
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(file, (__force const char __user *)buf, count, pos);
	set_fs(old_fs);

	return res;
}
static inline ssize_t tpcm_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	ssize_t result;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	result = vfs_read(file, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
#else
#define tpcm_kernel_read kernel_read
#define tpcm_kernel_write kernel_write
#endif

static inline void httc_gettimeofday(struct timeval *tv){
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0))
				struct timeval ntv;
				do_gettimeofday(&ntv);
				tv->tv_sec = ntv.tv_sec;
				tv->tv_usec = ntv.tv_usec;

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
#include <linux/timekeeping32.h>
				struct timespec ntv;
				getnstimeofday(&ntv);
				tv->tv_sec = ntv.tv_sec;
				tv->tv_usec = ntv.tv_nsec/1000;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) )
#include <linux/timekeeping.h>
                struct timespec64 ntv;
                ktime_get_real_ts64(&ntv);
				tv->tv_sec = ntv.tv_sec;
				tv->tv_usec = ntv.tv_nsec/1000;
#endif
}

#endif

#endif	/** __VERSION_H__ */

