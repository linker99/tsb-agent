#ifndef __AGENT_MODULE_AUDIT_H__
#define __AGENT_MODULE_AUDIT_H__

#include "sqlite3.h"
#include "tcfapi/tcf_log_notice.h"

#define AUDIT_ONCE_READ_MAX		100
#define AUDIT_TIMER_INTERVAL	(3 * 1000)

typedef struct audit_log {
        int type;
        sqlite3 *db;
        char topic[128];
        char *db_path;
		char *sql_fmt;
		sqlite3_stmt *stmt;
		void (*callback)(int, void *);
	int enable;	//是否关心此类日志
} audit_log_t;

enum audit_collect {
	AUDIT_OFF,	//不处理该日志
	AUDIT_ON	//处理该日志
};

static void audit_callback_sm(int index, void *data);
static void audit_callback_dm(int index, void *data);
static void audit_callback_warning(int index, void *data);

static int module_audit_init(void *master, void *args);
static int module_audit_exit(void *master, void *args);

#endif

