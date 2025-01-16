#include "agt_log.h"
#include "agt_util.h"
#include "agt_socket.h"

extern agent_t *g_master;
pthread_mutex_t socket_lock;


int socket_notify_read(agent_t *agent, int fd)
{
	int tmp, len = 0, mask = 0;

	do {
		tmp = len;
		len = read(fd, &mask, sizeof(int));
	} while (len > 0);

	return tmp == sizeof(int) ? mask : -1;
}


void socket_setnonblocking(int sock)
{
        int opts;

        opts = fcntl(sock, F_GETFL);
        opts = opts | O_NONBLOCK;
        fcntl(sock, F_SETFL, opts);
}


int agent_create_socket(agent_t *master)
{
	assert(master);

	/* 添加本地内部通信,并设pipe_fd[0]为读端,pipe_fd[1]为写端 */
	if(socketpair(PF_UNIX,SOCK_STREAM,0,master->pipe_fd) < 0){
		agent_log(HTTC_WARN, "create client fd fail!");
		return -1;
	}
	
	socket_setnonblocking(master->pipe_fd[0]);
	socket_setnonblocking(master->pipe_fd[1]);
	event_epoll_fd_add(master, master->pipe_fd[0], FD_FROM_LOCAL, 0);
	
	return 0;
}
