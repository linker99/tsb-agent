#ifndef __AGENT_EVENT_H__
#define __AGENT_EVENT_H__

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "rbtree.h"

#define MAX_FD			256
#define PACKET_HEAD		4
#define MAX_PACKET_LEN	(1024 * 1024)


#define PACKET_STATE_NONE          	0
#define PACKET_STATE_HEADER_FINISH 	1
#define PACKET_STATE_BODY_PART     	2
#define PACKET_STATE_BODY_FINISH   	3
#define PACKET_STATE_OVER          	4

enum {
	FD_FROM_LOCAL,
		
	FD_FROM_UNIX,
	FD_FROM_UNIX_REQUEST,
	
	FD_FROM_REMOTE,
	FD_FROM_REMOTE_REQUEST,
	
	FD_FROM_CENTRE
};

enum {
	FD_STATS_OK,
	FD_STATS_CLEAN,
	FD_STATS_DROP,
	FD_STATS_CONTINUE,
	FD_STATS_ADD
};

struct agent_event_tree {
        pthread_mutex_t lock;
        rbroot_t tree;
};

typedef struct agt_event{
	rbnode_t node;

	int fd;
	int fd_from;
	int status;
	size_t total_len;
	int cur_len;
	uint8_t *buffer;

	int is_update;
	int update_data;

	struct list_head list;
} agt_event_t;

void *event_run(void *agent);
int event_select_wait(void *master);
agt_event_t *event_epoll_fd_add(void *master, int fd, int attribute, int at_now);

#endif

