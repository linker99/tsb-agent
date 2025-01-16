#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
//#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <linux/rtnetlink.h>
#include <tpcm_debug.h>
#include "message.h"

//#define NETLINK_HTTCSEC_PROT    29
#define NETLINK_HTTCSEC_PROT    24
#define MAX_PAYLOAD 4096
#define MAX_MESSAGE_TYPE 128
struct netlink_listener{
	int sync;
	pthread_t thread_id;
	HTTCSEC_NETLINK_CALLBACK callbacks[MAX_MESSAGE_TYPE];
};
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile uint32_t port = 0x7FFFFFFE;
 //wanans 2022-1012_009
 static inline int netlink_create_socket(void) {
	return socket(AF_NETLINK, SOCK_RAW, NETLINK_HTTCSEC_PROT);
}
 //wanans 2022-1012_010
 static inline int netlink_bind(int sock_fd,int pid,int group) {
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = pid;
	addr.nl_groups = group;
	return bind(sock_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl));

}

 //wanans 2022-1012_011
 static int netlink_recv_message(int sock_fd, int *msgtype,unsigned char *message, int *len)
{
	int r;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl source_addr;
	struct iovec iov;
	struct msghdr msg;

	//create message
	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh) {
		perror("Fail to alloc message header\n");
		return -ENOMEM;

	}
	iov.iov_base = (void *) nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	memset(&source_addr, 0, sizeof(struct sockaddr_nl));
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &source_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if ((r = recvmsg(sock_fd, &msg, 0)) < 0) {
		perror("Fail to receive netlink message to receive!\n");
		free(nlh);
		return -3;
	}
	int payload_len = nlh->nlmsg_len - NLMSG_SPACE(0);
	if(msgtype)*msgtype = nlh->nlmsg_type;
	if(len){
		if(*len < payload_len){
			tpcm_debug("Insufficient buffer length %d,need %d,nessage type=%d\n",*len,payload_len,nlh->nlmsg_type);
			return -4;
		}
		//tpcm_debug("payload_len %d,nessage type=%d\n",payload_len,nlh->nlmsg_type);
		*len = payload_len;
		if(message)memcpy(message, (unsigned char *) NLMSG_DATA(nlh), payload_len);
	}

	free(nlh);
	return 0;
}


int netlink_send_message(int msgtype,int sock_fd, void *message, int len,unsigned int pid, unsigned int group){
	int r;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dest_addr;
	struct iovec iov;
	struct msghdr msg;

	//create message
	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(len));
	if (!nlh) {
		perror("Fail to alloc message header to send\n");
		return -ENOMEM;
	}
	nlh->nlmsg_len = NLMSG_SPACE(len);
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = msgtype;
	memcpy(NLMSG_DATA(nlh), message, len);
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;
	memset(&dest_addr, 0, sizeof(struct sockaddr_nl));

	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;//to kernel
	dest_addr.nl_groups = group;//is broadcast

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &dest_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	//send message

	if ((r = sendmsg(sock_fd, &msg, 0)) < 0) {
		perror("Fail to send message to kernel!\n");
		free(nlh);
		return r;
	}
	tpcm_debug("send message success\n");
	free(nlh);
	return 0;
}


int netlink_auto_bind(int sock_fd,int group){
	int lport;
	pthread_mutex_lock(&mutex);
	while(1){
			int r;
			lport = port++;
			if(port == 0x80000000)port = 2;
			r = netlink_bind(sock_fd,lport,group);
			if(!r)break;
			if(r == EADDRINUSE){
				tpcm_info("Address in use,we will try to rebind next port\n");
				continue;
			}
			perror("Netlink auto bind error\n");
			pthread_mutex_unlock(&mutex);
			return r;
	}
	pthread_mutex_unlock(&mutex);
	return lport;
}

//int netlink_auto_bind(int sock_fd,int group){
//	int opt = 1;
//	// sockfdΪ��Ҫ�˿ڸ��õ��׽���
//	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const voidvoid *)&opt, sizeof(opt));
//
//}


int  httcsec_netlink_send_msg(int msgtype,void *message, int len,char *obuffer,int *length){
		int r;
		//int loops = 0;
	    int sock_fd = netlink_create_socket();
	    unsigned char buffer[4096];
	    int lport;
		if (sock_fd < 0) {
			perror("Create netlink socket error");
			return sock_fd;
		}
	  	lport = netlink_auto_bind(sock_fd,0);
	  	if(lport < 0){
	  		return lport;
	  	}
	  	tpcm_debug("Netlink sender bind to port  %d\n",lport);
		if((r =  netlink_send_message(msgtype,sock_fd,message,len,lport,0))){
			goto out;
		};
		len = 4096;
		if ((r = netlink_recv_message(sock_fd,0, buffer, &len)) == 0 ) {
			tpcm_debug("received kernel response len : %d\n", len);
			if(obuffer && length){
				*length = *length < len?*length:len;
				memcpy(obuffer,buffer,*length);
			}
			else if(length){
				*length  =  len;
			}

		}
	out:
		close(sock_fd);
		return r;
}



struct netlink_listener_param{
	struct netlink_listener *listener;
	int sock;
    int length;
    int msg_type;
    unsigned char buffer[4096];
};

//wanans 2022-1012_013
 static int handle_kernel_notify(struct netlink_listener_param *param)
{

	  param->listener->callbacks[param->msg_type](param->msg_type,(char *)param->buffer,param->length);
	  free(param);
	  return 0;
	  //     struct network_auth_notify *nt = ( struct network_auth_notify *)param->buffer;
//       // tpcm_debug("id =%lu\n",nt->id);
//     tpcm_debug("Notify received id=%lu, type=%d,peer_addr=%d.%d.%d.%d,peer_port=%d,local_port=%d\n",
//        		nt->id,nt->type,NIPQUAD(nt->peer_addr),ntohs(nt->peer_port),
//        					ntohs(nt->local_port));
//     ret = netauth(nt);
//
//	struct network_auth_result r = {
//			.id = nt->id,
//			.key_length = 0,
//			.local_port = nt->local_port,
//			.peer_addr = nt->peer_addr,
//			.peer_port = nt->peer_port,
//			.result  = 1,
//			.socket = nt->socket,
//			.type = nt->type
//	};
//	if(ret != 0){
//		r.result = 0;//auth fail
//	}
//    tpcm_debug("AUTH RESULT %d\n",r.result);
//        //sleep(2);
//    if(ret == 0){
//		tpcm_debug("AuthClient Send CREATE connection to kernel type=%d,peer_addr=%d.%d.%d.%d,peer_port=%d,local_port=%d\n",
//				r.type,NIPQUAD(r.peer_addr),ntohs(r.peer_port),
//									ntohs(r.local_port));
//		tpcm_debug("send_to_kernel %d\n",send_to_kernel(
//				NL_COMMAND_NETAUTH_RESULT,
//				&r,sizeof(struct network_auth_result),0,0));
//    }

}




 //wanans 2022-1012_005
 HTTCSEC_NETLINK_HANLDLE httcsec_alloc_netlink_listener(void){
	struct netlink_listener *listener= malloc(sizeof(struct netlink_listener));
	if(listener){
		memset(listener,0,sizeof(struct netlink_listener));
	}
	return listener;
}
void httcsec_free_netlink_listener(HTTCSEC_NETLINK_HANLDLE handle){
	if(handle)free(handle);
}

 //wanans 2022-1012_006
 int httcsec_register_netlink_callback(HTTCSEC_NETLINK_HANLDLE  handle,
		int msgtype,
		HTTCSEC_NETLINK_CALLBACK callback){
	if(!handle ||  msgtype < 0 || msgtype >= MAX_MESSAGE_TYPE || !callback)return -1;
	struct netlink_listener *listener  = (struct netlink_listener *)handle;
	if(listener->callbacks[msgtype])return -2;
	listener->callbacks[msgtype] = callback;
	return 0;
}


 //wanans 2022-1012_008
 static void * netlink_main(void *arg)
{
		unsigned char cmd[1024] = {0};
		struct netlink_listener *listener  = (struct netlink_listener *)arg;
		int sock_fd = netlink_create_socket();
		int r;
        if (sock_fd < 0) {
        	tpcm_error("Create netlink socked error\n");
            return (void *)-1;
        }
	  	if((r = netlink_bind(sock_fd,1,1))){
	  		perror("Listener bind error");
	  		return (void *)(unsigned long)r;
	  	}
//	  	if(lport < 0){
//	  		return (void *)(unsigned long)lport;
//	  	}
		tpcm_info("netlink linster bind to port  %d\n",1);
		struct netlink_listener_param *param = 0;



		while (1){
			pthread_t thread_id;
			if(!param){
        		param = malloc(sizeof(struct netlink_listener_param));
        		if(!param){
        			tpcm_error("No memory ........\n");
					continue;
				}
        		param->listener = listener;
				param->sock = sock_fd;
        	}
        	param->length = 4096;
        //	int mesage_type;
        	int ret =  netlink_recv_message(param->sock,&param->msg_type,param->buffer,&param->length);

        	 if (ret < 0) {

        		tpcm_error("Receive message error %d\n",ret);
				continue;
				//return ret;
			 }
        	 if(param->msg_type <0 || param->msg_type >=MAX_MESSAGE_TYPE ){
        		 tpcm_error("Invalid netlink message type %d\n",param->msg_type);
        		 continue;
        	 }
        	 if(!listener->callbacks[param->msg_type]){
        		 tpcm_error("Netlink callback not register for message type %d\n",param->msg_type);
        		 continue;
        	 }

//			 if(param->length < sizeof(struct network_auth_notify)){
//				 tpcm_debug("Receive message length = %d ,not a network_auth_notify \n",ret);
//				 continue;
//				// return -1;
//			 }
			 if(pthread_create(&thread_id, NULL, (void *)handle_kernel_notify, (void *) param)){
				perror("fail to create kernel notify thread\n");
				continue;
			}
			pthread_detach(thread_id);
			param = 0;
        }
        return (void *)0;
}
 //wanans 2022-1012_007
 int httcsec_start_netlink_listener(HTTCSEC_NETLINK_HANLDLE handle,int sync){
	unsigned char cmd[1024];

	
	if(!handle)return -1;
	struct netlink_listener *listener  = (struct netlink_listener *)handle;
	if(sync){
			return (int)(unsigned long)netlink_main(listener);
	}
	else{
		 if(pthread_create(&listener->thread_id, NULL, (void *)netlink_main, (void *) listener)){
			 tpcm_error("pthread_create() error\n");
			return -1;
		 }
		 pthread_detach(listener->thread_id);
		 return 0;
	}
}
void httcsec_stop_netlink_listener(HTTCSEC_NETLINK_HANLDLE  handle){

}





