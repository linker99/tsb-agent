

#ifndef TCFAPI_TCF_LOG_NOTICE_H_
#define TCFAPI_TCF_LOG_NOTICE_H_
#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_notice.h"
#include "../tsbapi/tsb_admin.h"


/** 可信连接日志类型 */
enum{
	LOG_TNC_NEGOTIATION_OK = 1,//协商成功（可不输出日志）
	LOG_TNC_NEGOTIATION_FAIL,//协商失败
	LOG_TNC_CREATE_SESSION,//创建会话通知
	LOG_TNC_CREATE_DELETE,//(主动)删除会话通知
	LOG_TNC_SESSION_EXPIRE_ALL,//会话过期通知(被动删除)
	LOG_TNC_SESSION_EXPIRE_HALF//会话单向过期通知(双向变单向)
};

#pragma pack(push, 1)
struct log{
	unsigned int magic;
	unsigned int type;
	unsigned int operate;
	unsigned int result;
	unsigned int userid;
	int pid;
	int repeat_num;
	long time;
	int total_len;
	int len_subject;
	int len_object;
	char sub_hash[DEFAULT_HASH_SIZE];
	char data[0];  //主体名称+客体名
};

struct tnc_create_session_notice{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint64_t be_expire_time;
	uint32_t be_peer_addr;
	uint32_t be_is_bi_direction;
};

struct session_expire_notice_half{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint64_t be_next_expire_time;
	uint32_t be_peer_addr;
};

struct session_expire_or_delete_notice{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint32_t be_peer_addr;
};

/** 可信协商通知 */
struct tnc_disagreement_notice{
	uint64_t be_time;
	uint32_t be_peer_addr;
};

/** 可信连接日志 */
struct tnc_log{
	uint32_t action;
	uint32_t peer_addr;//协商和会话相关日志填写
	uint64_t local_session_id;//会话相关日志填写
	uint64_t peer_session_id;//会话相关日志填写
	uint64_t expire_time;//创建会话时填写
	uint32_t is_bi_direction;//创建会话时填写
	uint32_t error_code;//协商失败时填写。其余填0
};
#pragma pack(pop)

/*
 * 阻塞方式读取日志
 */
int tcf_read_logs(struct log ***logs, int *num_inout, unsigned int timeout);

/*
 * 非阻塞方式读取日志
 */
int tcf_read_logs_noblock(struct log ***logs, int *num_inout);
/*
 * 删除日志
 */
int tcf_remove_logs(struct log *log);
/*
 * 释放读取日志的内存空间
 */
int tcf_free_logs(int num,struct log **logs);

/** 写入日志 */
int tcf_write_logs (const char * data, int length);
/*
 * 删除所有日志
 */
int tcf_clear_all_logs();

/*
 * 创建通知读取队列
 */
int tcf_create_notice_read_queue(void);

/*
 * 关闭通知读取队列
 */
void tcf_close_notice_read_queue(int fd);

/*
 * 	写入内存通知。
 */
int tcf_write_notices(unsigned char *buffer, int length, int type);

/*
 * 	阻塞方式读取内存通知。
 */
int tcf_read_notices(int fd, struct notify **ppnode, int *num, unsigned int timeout);

/*
 * 	非阻塞方式读取内存通知。
 */
int tcf_read_notices_noblock(int fd, struct notify **ppnode, int *num);


#endif /* TCFAPI_TCF_LOG_NOTICE_H_ */
