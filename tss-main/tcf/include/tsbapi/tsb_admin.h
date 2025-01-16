/*
 * tsb_user.h
 *
 *  Created on: 2021年4月8日
 *      Author: wangtao
 */

#ifndef TSBAPI_TSB_ADMIN_H_
#define TSBAPI_TSB_ADMIN_H_

#include <stdint.h>
#include "../tcfapi/tcf_config_def.h"
#include "tsb_udisk.h"
#include "tsb_net.h"

//operate
enum {
	WHITELIST_OPERATE_EXEC = 0x1,
	CRITICAL_FILE_OPEN = 0x2,
};
enum {
	DMEASURE_OPERATE_PERIODICITY = 0x1,
	DMEASURE_TRIGGER = 0x2,
};

//CATEGORTY
enum {
	LOG_CATEGRORY_BMEASURE = 0x1,
	LOG_CATEGRORY_WHITELIST = 0x2,
	LOG_CATEGRORY_DMEASURE = 0x3,
	LOG_CATEGRORY_TNC = 0x4,
	LOG_CATEGRORY_WARNING = 0x5,
	LOG_CATEGRORY_ACCESS = 0x6,
	LOG_CATEGRORY_UDISK = 0x7,
	LOG_CATEGRORY_NET = 0x8,
	LOG_CATEGRORY_USER_INFO = 0x9,
	LOG_CATEGRORY_AUDIT_SUM,
};

/* udisk operate  */
enum
{
	UDISK_PLUG   = 0x1,
	UDISK_UNPLUG = 0x2,
	UDISK_SCAN = 0x3,
};

enum{
	LOG_TYPE_INFO= 0,//一般信息
	LOG_TYPE_PASS, //通过
	LOG_TYPE_ERROR//失败
};

//警告日志类型
enum {
	WARNING_LOG_WHITELIST = 0x1,
	WARNING_LOG_CRITICAL_CONFILE = 0x2,
};

//result
#define		RESULT_SUCCESS        1
#define		RESULT_FAIL           2
#define		RESULT_BYPASS         3
#define		RESULT_UNMEASURED     4

#define     	RESULT_UNMARK          5   /* udisk unmark */
#define     	RESULT_MARK_INVISIBLE  6   /* udisk marked but not visible */
#define     	RESULT_MARK_READ       7   /* udisk marked can read only */
#define     	RESULT_MARK_WRITE      8   /* udisk marked can read and write */

enum {
	RECORD_SUCCESS = 1,
	RECORD_FAIL = 2,
	RECORD_NO = 4,
	RECORD_ALL = 8,
};

#define MAX_NOTICE_SIZE 48

#pragma pack(push, 1)
struct log_n{
	uint16_t len;
	uint16_t category; //日志类型
	uint16_t type;     //结果类型
	uint16_t repeat_num;
	uint64_t time;
	char data[0];
};

struct log_warning{
	uint32_t warning_type;   //警告类型：白名单hash校验失败[1]   关键文件hash校验失败[2]
};
#pragma pack(pop)

struct notify
{
	int type;
	int length;
	char buf[MAX_NOTICE_SIZE];
};

/*
 * 	设置日志配置
 */
int tsb_set_log_config(const struct log_config *config);//可proc控制，查看

/*
 * 	重新加载日志配置
 */
int tsb_reload_log_config();

/*
 * 	读取日志配置
 */
int tsb_get_log_config(struct log_config *config);//可proc控制，查看

/*
 * 	轮转日志输出文件。
 */

int tsb_rotate_log_file();//
/*
 * 	读取内存日志。
 */
int tsb_read_inmem_log(unsigned char *buffer,int *length_inout,int *hasmore);

/*
 * 	非阻塞方式读取内存日志。
 */
int tsb_read_inmem_log_nonblock(unsigned char *buffer,int *length_inout,int *hasmore);

/*
 * 	设置通知队列长度(取值1000-2000)。
 */
int tsb_set_notice_cache_number(int num);

/*
 * 	创建通知读队列。
 */
int tsb_create_notice_read_queue();

/*
 *  close notify read queue
 */
void tsb_close_notice_read_queue(int fd);

/*
 * 	写通知。
 */
int tsb_write_notice( unsigned char *buffer, int length, int type );


int tsb_reload_cdrom_config(void);
int tsb_reload_udisk_config(void);

/*
 * 	阻塞方式读取通知。
 */
int tsb_read_notice(int fd, struct notify **ppnode, int *num);

/*
 * 	非阻塞方式读取通知。
 */
int tsb_read_notice_noblock(int fd, struct notify **ppnode, int *num);

int tsb_set_process_protect(void);

int tsb_set_unprocess_protect(void);
/*
 * 	重新加载动态度量策略
 */
int tsb_reload_dmeasure_policy();

/*
 * 	重新加载动态度量策略
 */
int tsb_set_dmeasure_policy(const char *data ,int length);

/*
 * 	增加进程度量策略
 */
int tsb_add_process_dmeasure_policy(const char *data ,int length);
/*
 * 删除进程度量策略
 */
int tsb_remove_process_dmeasure_policy(const char *data ,int length);
/*
 * 重新加载进程度量策略
 */
int tsb_reload_process_dmeasure_policy();

/*
 * 	重置进程追踪防护策略
 */
int tsb_set_ptrace_process_policy(const char *data ,int length);

/*
 * 	重新加载进程追踪防护策略
 */
int tsb_reload_ptrace_process_policy(void);

/*
 * 	重新加载全局控制策略
 */
int tsb_reload_global_control_policy();

/*
 * 	重新加载动态度量策略
 */
int tsb_set_global_control_policy(const char *data ,int length);

/*
 * 	重新加载重要配置文件策略
 */
int tsb_reload_critical_confile_integrity();


int tsb_add_file_integrity(const char *data ,int length);
int tsb_remove_file_integrity(const char *data ,int length);


int tsb_reload_file_integrity();



int tsb_set_process_ids(const char *data ,int length);
int tsb_set_process_roles(const char *data ,int length);
int tsb_reload_process_roles();
int tsb_reload_process_ids();

int tsb_set_tnc_policy(const char *data );

/*
 * tsb_file_select on notice and inmem log?
 */

/*
 * 	写用户态日志(入参data为结构体log_n)
 */
int write_user_log(const char *data ,int length);

/*
 * 	写用户态信息日志(入参data为结构体log_n的data域)
 */
int write_user_info_log(const char *data ,int length);

/*
 * 重新加载文件访问控制策略
 */
int tsb_reload_file_protect_policy();

/*
 * 重新加载特权进程策略
 */
//int tsb_reload_privilege_process_policy();

/*
 * 添加，删除及重载白名单程序文件访问控制策略
 */
int tsb_add_fac_whitelist_path_policy(const char *data ,int length);
int tsb_remove_fac_whitelist_path_policy(const char *data ,int length);
int tsb_reload_fac_whitelist_path_policy();

#endif /* TSBAPI_TSB_ADMIN_H_ */
