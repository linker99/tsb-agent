#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>

#define STR_NAME	512

enum {
	HTTC_DEBUG,
	HTTC_INFO,
	HTTC_WARN,
	HTTC_ERROR,
	HTTC_ABORT
};

typedef struct config_log {
	FILE	*fp;
	char	path[STR_NAME];
	int		size;
	int		level;
} config_log_t;

void tools_log_real(int level, const char *filename, int line, const char *format, ...);
#define tools_log(level, format, ...) tools_log_real(level, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define HTTC_NORM_LOGPATH	"/usr/local/httcsec/ttm/var/log/ht_whitelist.log"
#define HTTC_LOG_LEVEL   HTTC_DEBUG

void ht_getformat_time(char *cur_time);