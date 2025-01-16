#ifndef _HASH_WHITELIST_PATH_H
#define _HASH_WHITELIST_PATH_H

#include "sec_domain.h"

#define HASH_TAB_BITS	16
#define HASH_TAB_SIZE	(1<<HASH_TAB_BITS)
#define HASH_TAB_MASK	(HASH_TAB_SIZE-1)

#define PATH_LEN			512

struct whitelist_path {
	struct hlist_node list;
	char path[PATH_LEN];
};

int whitelist_path_init(void);
void whitelist_path_exit(void);

int query_whitelist_path(struct sec_domain *sec_d, int is_file_open);
int fac_whitelist_path_add(char *full_path);

#endif
