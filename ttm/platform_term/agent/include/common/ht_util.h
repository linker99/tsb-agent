#ifndef __HT_UTIL_H__
#define __HT_UTIL_H__

#include <stdlib.h>
#include <syslog.h>
#include <stdint.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <uuid/uuid.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"
#include "ht_def.h"
#include "ht_string.h"

int ht_init_getfile_hash(char *file_path, char *hash, char *uuid);
typedef int (*scan_file_callback)(const char* file_path, void *args);
unsigned long long ht_getmill_time();
void ht_getformat_time(char *cur_time);
int is_skip_dirs(const char *dir_name);
int is_skip_file_suffix(char *file_path);
int is_scan_file_suffix(char *file_path);
int is_exec(char *file_path, int g_time_first);
int ht_init_scan_dir(char *path, scan_file_callback scan_file_handle, void *args);
int ht_whitelist_uncompress(const char *tar_path, struct list_head *g_tar_list, int type);
int ht_scan_uncompress_all(const char *tar_path, struct list_head *g_tar_list, int type);

enum {
	FILE_COMPRESS_TAR = 1,
	FILE_COMPRESS_ZIP,
	FILE_COMPRESS_XZ
};

typedef struct decompression_func {

	int type;
	int (*decomression)(const char *, const char *);

} decompression_func_t;

int is_folder_empty(const char *path);
int tar_file_decompression(const char *tar_path, const char *temp_path);
int zip_file_decompression(const char *tar_path, const char *temp_path);
int xz_file_decompression(const char *tar_path, const char *temp_path);

typedef struct whitelist_exec_node_s {
	char uuid[UUID_LEN + 1];
	char file_path[PATH_MAX_LEN];
	char hash_str[HASH_LENGTH * 2 + 1];
	struct list_head tar_list;
} whitelist_exec_node_t;

#endif
