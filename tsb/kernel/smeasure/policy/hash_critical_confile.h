#ifndef _HASH_CRITICAL_CONFILE_H
#define _HASH_CRITICAL_CONFILE_H

//#include "hash_table.h"
#include "sec_domain.h"


struct critical_confile_digest {
	struct hlist_node list;
	__u8 digest[LEN_HASH];
	int len_name;
	char name[0];
};

int critical_confile_init(void);
void critical_confile_exit(void);



long ioctl_critical_confile_reload_policy(unsigned long param);

int load_critical_confile(void);

//int get_critical_confile_digest(const char *path, unsigned char *hash);
int get_critical_confile_digest(const char *path, unsigned char *hash_buf, int len);

int digest_cal_by_file(struct file *file, char *digest, int len);


#endif
