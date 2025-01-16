/*
 * message.h
 *
 *  Created on: 2011-6-16
 *      Author: wangtao
 */

#ifndef MESSAGE_H_
#define MESSAGE_H_
#include <stdint.h>
#include <linux/limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HTTCSEC_MISC_DEVICE_TYPE  0xAF
#define HTTC_IO_COMMAND(cmd)  _IO(HTTCSEC_MISC_DEVICE_TYPE,(cmd))

#define BMC_BUFF_LENGTH	1024*8

typedef void (* HTTCSEC_NETLINK_CALLBACK)(int msgtype,const char *buffer, int length);
typedef  void * HTTCSEC_NETLINK_HANLDLE;

int  httcsec_ioctl(unsigned long cmd,unsigned long param);
int  httcsec_netlink_send_msg(int msgtype,void *message, int len,char *obuffer,int *length);
HTTCSEC_NETLINK_HANLDLE httcsec_alloc_netlink_listener();
void httcsec_free_netlink_listener(HTTCSEC_NETLINK_HANLDLE handle);
int httcsec_start_netlink_listener(HTTCSEC_NETLINK_HANLDLE handle,int sync);
void httcsec_stop_netlink_listener(HTTCSEC_NETLINK_HANLDLE  handle);
int httcsec_register_netlink_callback(HTTCSEC_NETLINK_HANLDLE  handle,
		int msgtype,
		HTTCSEC_NETLINK_CALLBACK callback);
int netlink_send_message(int msgtype,int sock_fd, void *message, int len,unsigned int pid, unsigned int group);



#ifdef __cplusplus
}
#endif
#endif /* MESSAGE_H_ */
