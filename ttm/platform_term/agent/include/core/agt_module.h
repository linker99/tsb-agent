#ifndef __AGENT_MODULE_H__
#define __AGENT_MODULE_H__

#include "agt_util.h"
#include "agt_log.h"
#include "agt_event.h"

typedef int (*cmd_handle)(void *, void *);

#define	module_cmd_parse_packet(buf, root, body, request, response)	\
	do {	\
		root = cJSON_Parse(buf);	\
		body = cJSON_GetObjectItem(root, "body");	\
		request = cJSON_GetObjectItem(body, "request");	\
		response = cJSON_GetObjectItem(body, "response"); \
	} while (0);

enum module_type {
	AGENT_MODULE_AUDIT,

	AGENT_MODULE_MAX
};

enum {
	NOT_INIT = 0,
	HAS_INIT = 1,

	NOT_UPLOAD = 0,
	HAS_UPLOAD = 1,
};

enum {
	NV_INDEX_PLATFORM = 0xFF01,
	NV_INDEX_BMEASURE,
	NV_INDEX_SMEASURE,
	NV_INDEX_DMEASURE,
	NV_INDEX_KEYTREE,
	NV_INDEX_PROCESS_MANAGEMENT,
	NV_INDEX_POLICY_AUTH,
	NV_INDEX_AUDIT,
	NV_INDEX_STORE,
	NV_INDEX_PTRACE,
	NV_INDEX_TNC,
	NV_INDEX_FILEACL,
	NV_INDEX_MAX,
};

enum {
	MODULE_CMD_NONE = 0,
	MODULE_CMD_LOCAL = 1,
	MODULE_CMD_REMOTE = 2,
	MODULE_CMD_CENTER = 4,
};

enum {
	MODULE_CMD_TYPE_CENTER = 0,
	MODULE_CMD_TYPE_REMOTE,
	MODULE_CMD_TYPE_LOCAL,
	MODULE_CMD_TYPE_MAX,
};

typedef struct {
	int fd;
	int fd_from;
	cmd_handle cmd_exec;
	char buffer[0];
} module_task_ctx_t;

typedef struct agent_cmd {
	//char cmd_name[STR_NAME];
	char *cmd_names[MODULE_CMD_TYPE_MAX];
	int (*cmd_exec)(void *, void *);
	int cmd_support;
	struct list_head list;
} module_cmd_t;

typedef struct agent_module
{
	char name[STR_NAME];
	int nv_index;
	struct list_head list;
	struct list_head cmd_list;
	int (*module_init)(void *, void *);
	int (*module_exit)(void *, void *);

	int (*module_sync)(void *, void *);		//用于切换模式时，同步一些数据到管理中心
} agent_module_t;


int agent_module_init(agent_t *master);
void agent_module_exit(agent_t *master);

int module_write_init_flag(agent_t *agent, int index, int init);
int module_conf_is_init(agent_t *master, int module_type, int len);
int module_conf_init(agent_t *master, int module_type, unsigned char *conf, int conf_len);
int module_conf_read(agent_t *master, int module_type, unsigned char *conf, int *conf_len);
int module_conf_write(agent_t *master, int module_type, unsigned char *conf, int conf_len);

#endif

