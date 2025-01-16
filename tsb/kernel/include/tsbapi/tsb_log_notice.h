
#ifndef _TSB_LOG_NOTICE_H_
#define _TSB_LOG_NOTICE_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define MAX_NOTICE_SIZE 48 

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

/* udisk operate  */
enum
{
	UDISK_PLUG   = 0x1,      /* 靠USB靠靠 */
	UDISK_UNPLUG = 0x2,      /* 靠USB靠靠 */
	UDISK_SCAN = 0x3,         /* 靠縐SB靠 */
	UDISK_MARK = 0x4,        /* 靠USB靠 */
	UDISK_UNMARK = 0x5,      /* 靠USB靠靠 */
};

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
	unsigned char buf[MAX_NOTICE_SIZE];
};


int kernel_audit_log(const struct log_n *log_audit);


int tsb_put_notify(struct notify *entry);

#endif /* _TSB_LOG_NOTICE_H_ */
