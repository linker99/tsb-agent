#include "agt_util.h"
#include "agt_log.h"
#include "agt_event.h"
#include "agt_timer.h"
#include "agt_module.h"
#include "agt_socket.h"
#include "agt_notice.h"
#include "agt_config.h"
#include "tcfapi/tcf_log_notice.h"
#include "tcsapi/tcs_auth_def.h"

#include "cJSON.h"
#include "ht_string.h"

#define _GNU_SOURCE

agent_t bak_agent;

int g_first_load = 1;
unsigned long long g_counter = 0xFF;

static int __sym_def_compare(NODE_TYPE k1 ,NODE_TYPE k2);

static int __sym_def_compare(NODE_TYPE k1 ,NODE_TYPE k2){
	return k1 - k2;
}

static void __sym_timer_destroy(struct rb_node *node)
{
	rbnode_t *this = (rbnode_t *)container_of(node, rbnode_t, rbnode);
	agent_free(this);
}

static void __sym_event_destroy(struct rb_node *data)
{
	rbnode_t *this = (rbnode_t *)container_of(data, rbnode_t, rbnode);
	agt_event_t *event = (agt_event_t *)container_of(this, agt_event_t, node);

	close(event->fd);
	agent_free(event->buffer);

	agent_free(event);
}

agent_t *agent_create(agent_t **master)
{
	agent_t *agent = (agent_t *)agent_calloc(sizeof(agent_t));
	if(!agent) {
		fprintf(stderr, "no memory for malloc master!\n");
		return NULL;
	}

	memset(&bak_agent, 0, sizeof(agent_t));

	*master = agent;
	return agent;
}

agent_t *agent_init(agent_t *agent)
{
	if(g_first_load) {
		g_first_load = 0;
	}
	else {
		memset(agent, 0, sizeof(agent_t));

		agent->foreground = bak_agent.foreground;
		agent->conf_file = bak_agent.conf_file;
	}

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);

	pthread_condattr_t cattr;
	pthread_condattr_init(&cattr);
	pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	pthread_mutex_init(&agent->lock, &attr);
	pthread_cond_init(&agent->cond, &cattr);
	pthread_mutex_init(&log_lock, NULL);
	pthread_mutex_init(&socket_lock, NULL);
	pthread_mutex_init(&replay_counter_lock, NULL);

	INIT_LIST_HEAD(&agent->module_list);
	INIT_LIST_HEAD(&agent->task_list);
	INIT_LIST_HEAD(&agent->running_task_list);
	INIT_LIST_HEAD(&agent->fd_add_list);

	pthread_mutex_init(&agent->time_rbtree.lock, NULL);
	pthread_mutex_init(&agent->event_rbtree.lock, NULL);
	rbtree_init(&agent->time_rbtree.tree ,__sym_timer_destroy ,__sym_def_compare);
	rbtree_init(&agent->event_rbtree.tree ,__sym_event_destroy ,__sym_def_compare);

	return agent;
}

void *agent_worker_cleanup(void *args, int need_unlock)
{
	agent_t *master = (agent_t *)args;
	char pname[64] = {0};

	AGENT_WARNING_IGNORED("-Wimplicit-function-declaration");
	pthread_getname_np(pthread_self(), pname, sizeof(pname));
	AGENT_WARNING_RECOVER;

	if (need_unlock) {
		if(master->want_destroy) {
			master->want_destroy--;
		}
		pthread_mutex_unlock(&master->lock);
	}

	agent_log(HTTC_INFO, "agent pthread %s exit.", pname);

	pthread_exit(0);
}

void *worker_run(void *arg)
{
	agent_t *master = (agent_t *)arg;
	struct timeval begin, end;
	struct list_head *pos, *next;
	agent_task_t *task;
	struct timespec outtime;
	char pname[64] = {0};
	unsigned long long  used_time;

	/* 2毫秒，等待主线程设置完名称 */
	usleep(2000);
	
	pthread_getname_np(pthread_self(), pname, sizeof(pname));
	agent_log(HTTC_INFO, "agent pthread %s start.", pname);

	while(1) {
		pthread_mutex_lock(&master->lock);
		if (master->want_destroy) {
			agent_worker_cleanup(master, 1);
		}

		while(master->wait_task_number <= 0) {
			clock_gettime(CLOCK_MONOTONIC, &outtime);
			outtime.tv_sec += 1;
			pthread_cond_timedwait(&master->cond, &master->lock, &outtime);
			if (master->want_destroy) {
				agent_worker_cleanup(master, 1);
			}
		}

		list_for_each_safe(pos, next, &master->task_list) {
			task = list_entry(pos, agent_task_t, list);
			list_del(&task->list);
			break;
		}
		
		master->free_workers_number--;
		master->wait_task_number--;

		list_add_tail(&task->list, &master->running_task_list);
		master->running_task_number++;

		if (master->want_destroy) {
			agent_worker_cleanup(master, 1);
		}
		pthread_mutex_unlock(&master->lock);

		if(task->run) {
			gettimeofday(&begin, NULL);
			task->run((void *)master, (void *)task->ctx);
			gettimeofday(&end, NULL);
			
			used_time = (end.tv_sec * 1000 + end.tv_usec / 1000);
			used_time -= (begin.tv_sec * 1000 + begin.tv_usec / 1000);
			
			if(used_time >= 500) {
				agent_log(HTTC_WARN, "%s: function [%s], used time :%.3lf sec", pname, task->name, used_time / 1000.00);
			}
			else {
				//agent_log(HTTC_DEBUG, "%s: function [%s], used time :%.3lf sec", pname, task->name, used_time / 1000.00);
			}

		}
		
		pthread_mutex_lock(&master->lock);		
		master->free_workers_number++;

		list_del(&task->list);
		agent_free(task);

		master->running_task_number--;
		pthread_mutex_unlock(&master->lock);
	}
}

static void agent_set_pthread_name(pthread_t tid, int num)
{
	char buf[64] = {0};
	sprintf(buf, "worker_%d", num);
	
	AGENT_WARNING_IGNORED("-Wimplicit-function-declaration");
	pthread_setname_np(tid, buf);
	AGENT_WARNING_RECOVER;
}

int agent_create_workers(agent_t *master)
{
	if(!master)
		return -1;

	int i;
	int counts = master->config.common.work_threads;
	master->workers = (pthread_t *)agent_calloc(sizeof(pthread_t) * (counts + 4));
	if(!master->workers)
		return -1;

	pthread_setname_np(pthread_self(), "ht_agent");

	pthread_mutex_lock(&master->lock);
	for(i = 0; i < counts + 1; i++) {
		if(i == 0) {
			pthread_create(&master->workers[i], NULL, timer_run, (void *)master);
			pthread_setname_np(master->workers[i], "timer");
		}
		else {
			pthread_create(&master->workers[i], NULL, worker_run, (void *)master);
			agent_set_pthread_name(master->workers[i], i);
			master->free_workers_number++;
		}

		pthread_detach(master->workers[i]);
	}
	pthread_mutex_unlock(&master->lock);

	return 0;
}

int agent_running()
{
	int fd;
	const char *file_name = "/var/run/agent";

	fd = open(file_name, O_RDWR | O_CREAT, 0644);
	if(fd < 0) {
		return -1;
	}

	if(flock(fd, LOCK_EX | LOCK_NB) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;

}

void agent_destroy(agent_t *master)
{
	assert(master);

	int ret;
	
	/* 通知notice线程退出 */
	ret = tcf_write_notices(NULL, 0, NOTICE_BLOCK_EXIT);
	if (ret != 0) {
		agent_log(HTTC_WARN, "tcf_write_notices fail, ret=%08X", ret);
	}
	
	/* 停止工作线程 */
	master->want_destroy = master->config.common.work_threads;
	while(master->want_destroy) usleep(10000);

	agent_free(master->workers);

	/* 关闭log文件 */
	agent_log_destroy(master->foreground, &master->config.common.log);

	/* 清空定时器 */
	rbtree_destroy(&master->time_rbtree.tree);
	
	/* 清空event */
	rbtree_destroy(&master->event_rbtree.tree);
	close(master->epoll_fd);

	/* 关闭管道的1端（0端已关闭） */
	close(master->pipe_fd[1]);

	/* 释放锁 */
	pthread_mutex_destroy(&master->lock);
	pthread_cond_destroy(&master->cond);
	pthread_mutex_destroy(&log_lock);
	pthread_mutex_destroy(&socket_lock);
	pthread_mutex_destroy(&replay_counter_lock);
	pthread_mutex_destroy(&master->time_rbtree.lock);
	pthread_mutex_destroy(&master->event_rbtree.lock);

	/*释放task队列*/
	struct list_head *pos, *next;
	agent_task_t *task;
	list_for_each_safe(pos, next, &master->task_list) {
		task = list_entry(pos, agent_task_t, list);
		list_del(&task->list);

		agent_free(task->ctx);
		agent_free(task);
	}
	
	list_for_each_safe(pos, next, &master->running_task_list) {
		task = list_entry(pos, agent_task_t, list);
		list_del(&task->list);

		agent_free(task->ctx);
		agent_free(task);
	}

	/* 调用模块exit接口 */
	agent_module_exit(master);
	
	return;
}
