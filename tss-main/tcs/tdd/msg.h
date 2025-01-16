/*
 * msg.h
 *
 *  Created on: 2018年10月31日
 *      Author: wangtao
 */

#ifndef MSG_H_
#define MSG_H_
#define NETLINK_HTTCSEC_PROT    29
enum{
	NL_COMMAND_NETAUTH_RESULT = 0,
	NL_COMMAND_NETAUTH_BYPASS,
	NL_COMMAND_SIZE=256
};
typedef int (*COMMAND_HANDLER_NL)(void *input,int length,void *output,int *olen);
int httcsec_io_command_register_nl(int command,COMMAND_HANDLER_NL handler);
void httcsec_io_command_unregister_nl(int command);
int httcsec_io_send_message(void *data,int length,int type);
#endif /* MSG_H_ */
