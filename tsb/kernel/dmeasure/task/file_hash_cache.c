#include <linux/jhash.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include "common.h"
//#include "hash_table.h"
#include "file_hash_cache.h"
#include "utils/debug.h"

#define PATH_LEN			512
#define MAX_CACHE_NUMBER	8192

struct whitelist_cache {
	char path[PATH_LEN];
	char digest[LEN_HASH];
	int path_len;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct timespec64 file_mtime;
#else
	struct timespec file_mtime;
#endif
	loff_t file_size;
	int flag;
};

struct cache_array {
	struct whitelist_cache *wc[MAX_CACHE_NUMBER];
	rwlock_t wc_rwlock[MAX_CACHE_NUMBER];
};

static struct cache_array w_cache;
static unsigned int random;

static inline unsigned string_hash_key(unsigned int random, const char *p,
				       int n, unsigned int mask)
{
	return jhash(p, n, random) & mask;
}

int check_file_hash_cache(struct file *file, char *path, char *digest)
{
	int ret = 0;
	unsigned hash = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct timespec64 file_mtime;
#else
	struct timespec file_mtime;
#endif
	loff_t file_size;
	int len = strlen(path);

	if (len > PATH_LEN)
		len = PATH_LEN;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	file_mtime = file->f_inode->i_mtime;
	file_size = i_size_read(file->f_inode);
#else
	file_mtime = file->f_path.dentry->d_inode->i_mtime;
	file_size = i_size_read(file->f_path.dentry->d_inode);
#endif
	hash = string_hash_key(random, path, len, MAX_CACHE_NUMBER - 1);

	read_lock(&w_cache.wc_rwlock[hash]);
	if (w_cache.wc[hash] == NULL ||
	    w_cache.wc[hash]->flag == 0 ||
	    w_cache.wc[hash]->path_len != len ||
	    memcmp(w_cache.wc[hash]->path, path, len) ||
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	    memcmp(&w_cache.wc[hash]->file_mtime, &file_mtime,
		   sizeof(struct timespec64)) ||
#else
	    memcmp(&w_cache.wc[hash]->file_mtime, &file_mtime,
		   sizeof(struct timespec)) ||
#endif
	    w_cache.wc[hash]->file_size != file_size) {
		ret = -EINVAL;
		goto out;
	} else {
		memcpy(digest, w_cache.wc[hash]->digest, LEN_HASH);
	}
	//DEBUG_MSG(DEBUG_FOR_LOG, "enter[%s]:[%s]\n", __func__, path);

out:
	read_unlock(&w_cache.wc_rwlock[hash]);

	return ret;
}

//EXPORT_SYMBOL(check_file_hash_cache);

int set_file_hash_cache(struct file *file, char *path, char *digest)
{
	int ret = 0;
	unsigned hash = 0;
	int len = strlen(path);

	hash = string_hash_key(random, path, len, MAX_CACHE_NUMBER - 1);

	write_lock(&w_cache.wc_rwlock[hash]);
	if (w_cache.wc[hash] == NULL) {
		ret = -EINVAL;
		goto err;
	}
	if (w_cache.wc[hash]->flag != 0)
		memset(w_cache.wc[hash], 0, sizeof(struct whitelist_cache));
	if (len < PATH_LEN) {
		memcpy(w_cache.wc[hash]->path, path, len);
		w_cache.wc[hash]->path_len = len;
	} else {
		memcpy(w_cache.wc[hash]->path, path, PATH_LEN);
		w_cache.wc[hash]->path_len = PATH_LEN;
	}
	memcpy(w_cache.wc[hash]->digest, digest, LEN_HASH);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	w_cache.wc[hash]->file_size = i_size_read(file->f_inode);
	w_cache.wc[hash]->file_mtime = file->f_inode->i_mtime;
#else
	w_cache.wc[hash]->file_size = i_size_read(file->f_path.dentry->d_inode);
	w_cache.wc[hash]->file_mtime = file->f_path.dentry->d_inode->i_mtime;
#endif
	w_cache.wc[hash]->flag = 1;
	DEBUG_MSG(HTTC_TSB_DEBUG, "enter[%s]:[%s]\n", __func__, path);
err:
	write_unlock(&w_cache.wc_rwlock[hash]);

	return ret;
}

//EXPORT_SYMBOL(set_file_hash_cache);


/*
void file_hash_cache_clean(void)
{
	int i = 0;

	 //DEBUG_MSG(HTTC_TSB_DEBUG, "clean whitelist policy cache!\n");
	for (i = 0; i < MAX_CACHE_NUMBER; i++) {
		write_lock(&w_cache.wc_rwlock[i]);
		if (w_cache.wc[i] != NULL) {
			w_cache.wc[i]->flag = 0;
			memset(w_cache.wc[i], 0,
			       sizeof(struct whitelist_cache));
		}
		write_unlock(&w_cache.wc_rwlock[i]);
	}
	return;
}
*/

void file_hash_cache_free(void)
{
	int i = 0;

	for (i = 0; i < MAX_CACHE_NUMBER; i++) {
		if (w_cache.wc[i] != NULL) {
			kfree(w_cache.wc[i]);
			w_cache.wc[i] = NULL;
		}
	}
	return;
}

int file_hash_cache_init(void)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < MAX_CACHE_NUMBER; i++) {
		rwlock_init(&w_cache.wc_rwlock[i]);
		w_cache.wc[i] = NULL;
	}

	for (i = 0; i < MAX_CACHE_NUMBER; i++) {
		w_cache.wc[i] =
		    (struct whitelist_cache *)
		    kzalloc(sizeof(struct whitelist_cache), GFP_KERNEL);
		if (w_cache.wc[i] == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}
		w_cache.wc[i]->flag = 0;
	}

	get_random_bytes(&random, sizeof(random));
	DEBUG_MSG(HTTC_TSB_DEBUG, "file hash cache init success!\n");
	return ret;

err_out:
	file_hash_cache_free();
	return ret;
}

void file_hash_cache_exit(void)
{
	int i = 0;

	for (i = 0; i < MAX_CACHE_NUMBER; i++) {
		write_lock(&w_cache.wc_rwlock[i]);
		if (w_cache.wc[i] != NULL) {
			kfree(w_cache.wc[i]);
			w_cache.wc[i] = NULL;
		}
		write_unlock(&w_cache.wc_rwlock[i]);
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "file hash cache exit success!\n");
	return;
}
