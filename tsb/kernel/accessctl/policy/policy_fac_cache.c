#include <linux/jhash.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/module.h>

#include "policy_fac_cache.h"
#include "utils/debug.h"

struct policy_cache {
	char sub_hash[LEN_HASH];
	char obj_name[OBJ_NAME_LEN];
	int obj_len;
	time_t start_time;
	time_t end_time;
	int result;
	int flag;
};

struct policy_cache_array {
	struct policy_cache *pc[MAX_CACHE_NUMBER];
	rwlock_t pc_rwlock[MAX_CACHE_NUMBER];
};

static struct policy_cache_array p_cache;
static unsigned int random;

static inline unsigned string_hash_key(unsigned int random, const char *p,
				       int n, unsigned int mask)
{
	return jhash(p, n, random) & mask;
}





