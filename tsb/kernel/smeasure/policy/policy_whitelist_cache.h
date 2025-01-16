#ifndef _POLICY_WHITELIST_CACHE
#define _POLICY_WHITELIST_CACHE

int check_whitelist_cache(struct file *file, char *path, char *digest);
int set_whitelist_cache(struct file *file, char *path, char *digest);
void policy_whitelist_cache_clean(void);
int policy_whitelist_cache_init(void);
void policy_whitelist_cache_exit(void);

#endif
