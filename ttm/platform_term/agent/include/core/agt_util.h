#ifndef __AGT_UTIL_H__
#define __AGT_UTIL_H__

#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <ctype.h>
#include <fcntl.h>
#include <endian.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/types.h>

#include "list.h"
#include "rbtree.h"
#include "cJSON.h"

#include "ht_def.h"
#include "ht_string.h"
#include "ht_mem.h"
#include "ht_util.h"
#include "ht_crypt.h"

#include "agt_config.h"
#include "agt_timer.h"
#include "agt_event.h"

#include "sm/sm2_if.h"
#include "tcsapi/tcs_attest_def.h"

#define AGENT_ID_LEN			32
#define AGENT_MAX_MOD_SPACE		128

enum {
	OFFLINE,
	ONLINE,
};

enum {
	AGENT_STATE_NORMAL = 0,
	AGENT_STATE_MODE_SWITCHING,
};

typedef struct agent_task_s {
	int (*run)(void *, void *);
	char name[128];
	void *ctx;
	struct list_head list;
} agent_task_t;

typedef struct sign_key_s {
	/* 本地公私钥,      用来签名本地策略         */
	unsigned char prikey[PRIKEY_LENGTH];
	unsigned char pubkey[PUBKEY_LENGTH];
} sign_key_t;

struct encrypt_info {
	unsigned char center_pubkey[PUBKEY_LENGTH];	/* 中心公钥 */
	unsigned char local_prikey[PRIKEY_LENGTH];	/* 本地私钥 */
	unsigned char comkey[SM4_LOCAL_LENGTH];		/* 加密秘钥 */

	int auditkey_index;				/* kafka序号 */
	unsigned char auditkey[SM4_LOCAL_LENGTH];	/* kafka加密秘钥 */
};

typedef struct agent {
	/* 启动参数 */
	int foreground;
	int want_destroy;
	int mode_switching;
	char root_path[ROOT_PATH_LEN];
	const char *conf_file;

	/* 定时器rbtree */
	struct agent_time_tree time_rbtree;
	
	/* module链表 */
	struct list_head module_list;
	
	/* module初始化标识（从外部读取） */
	unsigned short module_is_init[AGENT_MAX_MOD_SPACE];

	/* 配置相关变量 */
	agent_config_t config;

	/* 终端标识，对应license里的id */
	char id[AGENT_ID_LEN + 1];
	
	/* 签名信息 */
	sign_key_t handle;
	char tpcm_id[ID_LENGTH + 1];
	
	/* 内部通信fd */
	int epoll_fd;
	int pipe_fd[2];
	struct list_head fd_add_list;
	struct agent_event_tree event_rbtree;

	/* 主动连接fd */
	int client_fd;
	int be_addr;

	/* 通信加密相关 */
	struct encrypt_info encrypt_key;

	/* 线程相关的信号变量 */
	pthread_t *workers;
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	unsigned int free_workers_number;

	/* 线程之间的队列 */
	unsigned int wait_task_number;
	unsigned int running_task_number;
	struct list_head task_list;
	struct list_head running_task_list;
} agent_t;

int agent_running();
agent_t *agent_init(agent_t *agent);
void agent_destroy(agent_t *master);
agent_t *agent_create(agent_t **master);
int agent_create_socket(agent_t *master);
int agent_create_workers(agent_t *master);
void *agent_worker_cleanup(void *args, int need_unlock);

extern agent_t bak_agent;
extern pthread_mutex_t replay_counter_lock;

#endif
