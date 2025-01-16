#ifndef __AGENT_LOG_H__
#define __AGENT_LOG_H__

#include <stdarg.h>
#include "agt_util.h"

#define TIME_STR	21



#define LOG_FILE_MAX_COUNT	3	

enum {
	HTTC_DEBUG,
	HTTC_INFO,
	HTTC_WARN,
	HTTC_ERROR,
	HTTC_ABORT
};

void agent_log_real(int level, const char *filename, int line, const char *format, ...);
#define agent_log(level, format, ...) agent_log_real(level, __FILE__, __LINE__, format, ##__VA_ARGS__)

#define CHECK(fun) \
	do { \
		if(fun) \
		agent_log(HTTC_ABORT, "%s fail", #fun); \
	} while(0);

extern pthread_mutex_t log_lock;

int agent_log_init(agent_t *agent);

int agent_log_destroy(int foreground, config_log_t *log);

#endif
