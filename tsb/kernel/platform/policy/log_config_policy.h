#ifndef LOG_CONFIG_POLICY_H_
#define LOG_CONFIG_POLICY_H_

#include "sec_domain.h"

enum {
	RECORD_SUCCESS = 1,
	RECORD_FAIL = 2,
	RECORD_NO = 4,
	RECORD_ALL = 8,
};

struct log_config{
	//	int log_level;
	int program_log_level;
	int dmeasure_log_level;
	//	int study_log_on;//白名单学习日志输出开关
	int log_buffer_on;//日志持久缓存开关
	int log_integrity_on;//日志完整性检查开关
	unsigned int log_buffer_limit;//日志缓存大小限制(mb)
	unsigned int log_buffer_rotate_size;//日志缓存轮转大小
	unsigned int log_buffer_rotate_time;//日志缓存轮转大小(hours)
	unsigned int log_inmem_limit;//无缓冲时日志内存大小限制(mb)
};

int log_config_policy_init(void);
void log_config_policy_exit(void);
int get_log_config_policy(int type, int result, struct sec_domain *sec_d);

#endif /* LOG_CONFIG_POLICY_H_ */
