#include "agt_util.h"
#include "agt_log.h"
#include "agt_event.h"
#include "agt_socket.h"
#include "agt_module.h"
#include "agt_timer.h"


/* at_now代表是否立即添加, epoll线程传1, 其它线程传0 */
agt_event_t *event_epoll_fd_add(void *agent, int fd, int fd_from, int at_now)
{
	agent_t *master = (agent_t *)agent;
	struct epoll_event ev;

	agt_event_t *fd_args = (agt_event_t *)agent_calloc(sizeof(agt_event_t));
	if(!fd_args) {
		agent_log(HTTC_WARN, "warnning, fail to malloc to agt_event_t!");
		return NULL;
	}

	fd_args->fd = fd_args->node.key = fd;
	fd_args->fd_from = fd_from;

	pthread_mutex_lock(&master->event_rbtree.lock);
	rbtree_push(&master->event_rbtree.tree, &fd_args->node);
	pthread_mutex_unlock(&master->event_rbtree.lock);

	if(at_now) {
		ev.data.fd = fd;
		ev.events = EPOLLIN;
		ev.data.ptr = (void *)fd_args;

		epoll_ctl(master->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	}
	else
		list_add_tail(&fd_args->list, &master->fd_add_list);

	agent_log(HTTC_DEBUG, "epoll add fd: %d, fd_from: %d, at_now: %d", fd, fd_from, at_now);
	return fd_args;
}


int event_select_wait(void *agent)
{
	assert(agent);
	agent_t *master = (agent_t *)agent;
	fd_set reads;
	int cmd, care_fd = master->pipe_fd[1];
	struct list_head *pos, *next;
	const agent_task_t *task;
	unsigned char task_info[512] = {0};
	
	agent_log(HTTC_INFO, "master wait for new signal!\n");
	while(1) {
		FD_ZERO(&reads);
		FD_SET(care_fd, &reads);
		struct timeval tm = {10, 0};
		if(select(care_fd + 1, &reads, NULL, NULL, &tm) <= 0) {

			pthread_mutex_lock(&master->lock);
			
			if (master->running_task_number > 0) {
				list_for_each_safe(pos, next, &master->running_task_list) {
					task = list_entry(pos, agent_task_t, list);
					snprintf(task_info+strlen(task_info), sizeof(task_info)-strlen(task_info)-1, "{%s}", task->name);
				}
			}

			agent_log(HTTC_INFO, "++++free:[%u], wait:[%u], running:[%u], running_tasks:[%s]++++",
								master->free_workers_number, master->wait_task_number,
								master->running_task_number, task_info);
			memset(task_info, 0, sizeof(task_info));
			
			pthread_mutex_unlock(&master->lock);
			
			continue;
		}

		if(!FD_ISSET(care_fd, &reads)) {
			agent_log(HTTC_WARN, "unexpect select event!");
			continue;
		}
		cmd = socket_notify_read(master, care_fd);

		if(cmd == HTTC_RELOAD) {
			agent_log(HTTC_INFO, "agent recv reload signal, contiune!");
			agent_destroy(master);
			return cmd;
		}
		else if (cmd == HTTC_EXIT) {
			agent_log(HTTC_INFO, "agent recv exit signal, exit ok!");
			agent_destroy(master);
			agent_free(master);
			exit(cmd);

			break;
		}
		else {
			agent_log(HTTC_INFO, "agent recv uknown signal, %d!", cmd);
		}
	}
}
