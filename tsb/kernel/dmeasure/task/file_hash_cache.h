#ifndef _FILE_HASH_CACHE
#define _FILE_HASH_CACHE

int check_file_hash_cache(struct file *file, char *path, char *digest);
int set_file_hash_cache(struct file *file, char *path, char *digest);
void file_hash_cache_clean(void);
int file_hash_cache_init(void);
void file_hash_cache_exit(void);

#endif
