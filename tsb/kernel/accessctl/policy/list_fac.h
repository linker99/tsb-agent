#ifndef _LIST_OBJECT_WILDCARD_H
#define _LIST_OBJECT_WILDCARD_H

#include <linux/list.h>
#include "sec_domain.h"
#include "common.h"

#define GUID_LEN 64

#define ORDINARY	0
#define WILDCARD	1

enum{
	PASS,
	CONTROL_WRITE,
	CONTROL_READ,
};

struct dac_policy{
	struct list_head list;

	uint32_t privi_type;//ALL ,READ_ONLY
	unsigned char process_hash[LEN_HASH];
	char sub_name[256];  //主体路径（特权进程全路径）
};

struct mac_policy{
	struct list_head list;
	struct list_head list_dac;

	uint8_t measure_flags;
	uint8_t type;//wirte_protect,read_protect
	uint16_t privileged_process_num;
	char obj_name[256];  //客体路径（需要保护的文件全路径）
};

void list_fac_init(void);
void list_fac_exit(void);
int is_empty_mac_policy(void);

int query_fac_policy_state(struct sec_domain *sec_d, int is_file_open);
int query_dir_segment_fac_policy_state(struct sec_domain *sec_d, int is_file_open);

int calc_sub_hash(const char *fullpath, unsigned char *hash, int is_file_open);

#endif
