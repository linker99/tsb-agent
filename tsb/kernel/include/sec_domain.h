#ifndef _SEC_DOMAIN_H
#define _SEC_DOMAIN_H

#include <linux/version.h>
#include <linux/ktime.h>
#include "common.h"

#define LEN_NAME_MAX    512

struct sec_domain {
	int super_flag;
	char sub_name[LEN_NAME_MAX];
	char obj_name[LEN_NAME_MAX];
	int sub_len;
	int obj_len;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_t start_time;
	ktime_t end_time;
#else
	time_t start_time;
	time_t end_time;
#endif
	int result;
	char sub_hash[LEN_HASH];
};

#endif
