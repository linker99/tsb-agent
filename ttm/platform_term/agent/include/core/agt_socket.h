#ifndef __AGENT_SOCKET_H__
#define __AGENT_SOCKET_H__

extern pthread_mutex_t socket_lock;

int socket_notify_read(agent_t *master, int fd);
void socket_setnonblocking(int sock);
int socket_fd_write_center(int fd, cJSON *root);

int agent_create_socket(agent_t *master);
#endif
