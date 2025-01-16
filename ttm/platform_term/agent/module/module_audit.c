#include <sys/types.h>
#include <pwd.h>

#include "agt_timer.h"
#include "agt_util.h"
#include "agt_module.h"
#include "agt_socket.h"
#include "tsbapi/tsb_admin.h"
#include "module/module_audit.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_log_notice.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_config.h"

static int AUDIT_NEXT_INDEX(audit_log_t *audit, int i, int sum)
{
	int next = i;
        while(next++){
                if(next >= sum || audit[next].enable)
                        break;
        };

        return next - i;
}

#define list_for_all_enable_items(i, sum)	\
		for(i = LOG_CATEGRORY_WHITELIST; i < sum; i += AUDIT_NEXT_INDEX(audit_logs, i, sum))

pthread_mutex_t g_audit_lock;

agent_module_t agent_module_audit = {
	.name = "audit",
	.nv_index = NV_INDEX_AUDIT,
	.list = {NULL, NULL},
	.cmd_list = {NULL, NULL},
	.module_init = module_audit_init,
	.module_exit = module_audit_exit,
	.module_sync = NULL,
};

audit_log_t audit_logs[LOG_CATEGRORY_AUDIT_SUM] = {
	{
        0,
        NULL,
        "",
        "",
        "",
        NULL,
        NULL,
	AUDIT_OFF
    },
    {
        LOG_CATEGRORY_WHITELIST,
        NULL,
        "smeasure",
        "audit_sm.db",
        "insert into audit('time', 'user', 'pid', 'subject', 'object', 'hash', 'operate', 'result', 'count') values(?,?,?,?,?,?,?,?,?)",
        NULL,
        audit_callback_sm,
	AUDIT_ON
    },
    {
        LOG_CATEGRORY_DMEASURE,
        NULL,
        "dmeasure",
        "audit_dm.db",
        "insert into audit('time', 'subject', 'object', 'hash', 'type', 'result', 'count') values(?,?,?,?,?,?,?)",
        NULL,
        audit_callback_dm,
	AUDIT_ON
    },
    {
        LOG_CATEGRORY_WARNING,
        NULL,
        "warning",
        "audit_warning.db",
        "insert into audit('time', 'warning_type') values(?,?)",
        NULL,
        audit_callback_warning,
	AUDIT_ON
    }
};


static int audit_db_clean(agent_t *agent)
{
	int i;

	list_for_all_enable_items(i, LOG_CATEGRORY_AUDIT_SUM) {
		if(audit_logs[i].db) {
			sqlite3_close(audit_logs[i].db);
			audit_logs[i].db = NULL;
		}
	}

	return 0;
}

static int audit_db_init(agent_t *agent)
{
	int i;
	char path[256] = {0};

	list_for_all_enable_items(i, LOG_CATEGRORY_AUDIT_SUM) {
		if(audit_logs[i].db)
			continue;

		/* 初始化连接数据库 */
		snprintf(path, sizeof(path) - 1, "%s/db/%s", agent->root_path, audit_logs[i].db_path);
		if(sqlite3_open(path, &audit_logs[i].db) != SQLITE_OK) {
			agent_log(HTTC_ERROR, "open db [%s] fail, errmsg: %s\n", path, sqlite3_errmsg(audit_logs[i].db));
			goto clean;
		}
		memset(path, 0, sizeof(path));
	}

	return 0;

clean:
	audit_db_clean(agent);
	return -1;
}

static void audit_callback_sm(int index, void *data)
{
	char subject[256] = {0};
	char object[256] = {0};
	char hash[DEFAULT_HASH_SIZE * 2 + 1] = {0};
	struct log *logs = (struct log *)data;
	struct passwd *pw_ptr = getpwuid(logs->userid);

	strncpy(subject, logs->data, logs->len_subject);
	strncpy(object, logs->data + logs->len_subject, logs->len_object);
	binary_to_str(logs->sub_hash, hash, DEFAULT_HASH_SIZE * 2);
	
	sqlite3_bind_int64(audit_logs[index].stmt, 1, (sqlite3_int64)logs->time);
	sqlite3_bind_text(audit_logs[index].stmt, 2, pw_ptr ? pw_ptr->pw_name : "", -1, SQLITE_STATIC);
	sqlite3_bind_int(audit_logs[index].stmt, 3, logs->pid);
	sqlite3_bind_text(audit_logs[index].stmt, 4, subject, -1, SQLITE_STATIC);
	sqlite3_bind_text(audit_logs[index].stmt, 5, object, -1, SQLITE_STATIC);
	sqlite3_bind_text(audit_logs[index].stmt, 6, hash, -1, SQLITE_STATIC);
	sqlite3_bind_int(audit_logs[index].stmt, 7, logs->operate);
	sqlite3_bind_int(audit_logs[index].stmt, 8, logs->result);
	sqlite3_bind_int(audit_logs[index].stmt, 9, logs->repeat_num);
	sqlite3_step(audit_logs[index].stmt);
	sqlite3_reset(audit_logs[index].stmt);
}

static void audit_callback_dm(int index, void *data)
{
	char subject[256] = {0};
	char object[256] = {0};
	char hash[DEFAULT_HASH_SIZE * 2 + 1] = {0};
	struct log *logs = (struct log *)data;

	strncpy(subject, logs->data, logs->len_subject);
	strncpy(object, logs->data + logs->len_subject, logs->len_object);
	binary_to_str(logs->sub_hash, hash, DEFAULT_HASH_SIZE * 2);

	sqlite3_bind_int64(audit_logs[index].stmt, 1, (sqlite3_int64)logs->time);
	sqlite3_bind_text(audit_logs[index].stmt, 2, subject, -1, SQLITE_STATIC);
	sqlite3_bind_text(audit_logs[index].stmt, 3, object, -1, SQLITE_STATIC);
	sqlite3_bind_text(audit_logs[index].stmt, 4, hash, -1, SQLITE_STATIC);
	sqlite3_bind_int(audit_logs[index].stmt, 5, logs->operate);
	sqlite3_bind_int(audit_logs[index].stmt, 6, logs->result);
	sqlite3_bind_int(audit_logs[index].stmt, 7, logs->repeat_num);
	sqlite3_step(audit_logs[index].stmt);
	sqlite3_reset(audit_logs[index].stmt);
}

static void audit_callback_warning(int index, void *data)
{
	struct log *logs = (struct log *)data;
	
	sqlite3_bind_int64(audit_logs[index].stmt, 1, (sqlite3_int64)logs->time);
	sqlite3_bind_int(audit_logs[index].stmt, 2, *(uint32_t *)logs->data);
	sqlite3_step(audit_logs[index].stmt);
	sqlite3_reset(audit_logs[index].stmt);
}

static int audit_read_logs_real(void *master, void *args, int *read_count)
{
	int i, ret, index, num_count = AUDIT_ONCE_READ_MAX;
	agent_t *agent = (agent_t *)master;
	int db_max_item = agent->config.modules.audit.db_clear_max_items;
	int count_type[LOG_CATEGRORY_AUDIT_SUM] = {0};
	struct log **logs = NULL;
	char sql[256] = {0}; 
	char *errmsg = NULL;
	
	if((ret = tcf_read_logs_noblock(&logs, &num_count)) != 0) {
		agent_log(HTTC_WARN, "tcf_read_logs_noblock fail! ret :%08X", ret);
		tcf_free_logs(num_count, logs);
		return -1;		
	}

	if(num_count <= 0 || logs == NULL) {
		tcf_free_logs(num_count, logs);
		return 0;
	}
	*read_count = num_count;

	agent_log(HTTC_INFO, "read audit number: [%d]", num_count);

	pthread_mutex_lock(&g_audit_lock);
	
	if(audit_db_init(agent) != 0) {
		pthread_mutex_unlock(&g_audit_lock);
		return HTTC_ERR_INIT;
	}

	/* 事务开始 */
	list_for_all_enable_items(i, LOG_CATEGRORY_AUDIT_SUM) {
		sqlite3_exec(audit_logs[i].db, "begin;", 0, 0, 0);
		sqlite3_prepare_v2(audit_logs[i].db, audit_logs[i].sql_fmt, strlen(audit_logs[i].sql_fmt), &audit_logs[i].stmt, 0);
	}

	/* 解析日志结构 */
	for(i = 0; i < num_count; i++) {
		if(logs[i]->type == 0x2) {
			index = LOG_CATEGRORY_WHITELIST;
		}
		else if(logs[i]->type == 0x3) {
			index = LOG_CATEGRORY_DMEASURE;
		}
		else if(logs[i]->type == 0x5) {
			index = LOG_CATEGRORY_WARNING;
		}
		else {
			agent_log(HTTC_ERROR, "error audit type: [%d]", index);
			continue;
		}

		if(!audit_logs[index].enable) continue;

		count_type[index]++;
		audit_logs[index].callback(index, logs[i]);
	}
		
	/* 清除指定条数以前的数据 */
	sprintf(sql, "delete from audit where id in (select id from audit order by id desc limit -1 offset %d)", db_max_item);

	/* 事务结束 */
	list_for_all_enable_items(i, LOG_CATEGRORY_AUDIT_SUM) {
		sqlite3_finalize(audit_logs[i].stmt);
		sqlite3_exec(audit_logs[i].db, "commit;", 0, 0, 0);

		if (sqlite3_exec(audit_logs[i].db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
			agent_log(HTTC_WARN, "exec sql [%s] fail, message :[%s],db-name :[%s]", sql, errmsg, audit_logs[i].db_path);
		}
	}

	audit_db_clean(agent);
	pthread_mutex_unlock(&g_audit_lock);

	agent_log(HTTC_INFO, " whitelist [%d], dmeasure [%d],  warning [%d], ",
							count_type[LOG_CATEGRORY_WHITELIST], count_type[LOG_CATEGRORY_DMEASURE],
							count_type[LOG_CATEGRORY_WARNING]);
	
	/* 删除日志 */
	if ((ret = tcf_remove_logs(logs[num_count - 1])) != 0) {
		agent_log(HTTC_WARN, "tcf_remove_logs fail, ret=%08X", ret);
		tcf_free_logs(num_count, logs);
		return -1;
	}

	tcf_free_logs(num_count, logs);
		
	return 0;
}

static int audit_read_logs(void *master, void *args)
{
	int ret, read_count;

	while (1) {
		read_count = 0;
		
		ret = audit_read_logs_real(master, args, &read_count);
		if (ret != 0 || read_count < AUDIT_ONCE_READ_MAX) {
			break;
		}

		agent_log(HTTC_INFO, "too many logs, read without sleep");
	}

	return ret;
}

static void audit_add_timer(void *agent, void *args)
{
	agent_t *master = (agent_t *)agent;

	timer_add_cycle(master, AUDIT_TIMER_INTERVAL, audit_read_logs);
}

static int module_audit_init(void *master, void *args)
{
	pthread_mutex_init(&g_audit_lock, NULL);
	
	audit_add_timer(master, args);

	return HTTC_OK;
}

static int module_audit_exit(void *master, void *args)
{
	pthread_mutex_destroy(&g_audit_lock);

	return 0;
}
