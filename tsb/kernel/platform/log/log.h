/*
 * log.h
 */

#ifndef SRC_LOG_LOG_H_
#define SRC_LOG_LOG_H_

#include "sec_domain.h"

enum{

	LOG_CATEGORY_MEASURE = 1,
	LOG_CATEGORY_CONTROL,
	LOG_CATEGORY_SYSTEM,
	LOG_CATEGORY_OTHER

};
enum{
	LOG_TYPE_INTERCEPT_MEASURE = 1,
	LOG_TYPE_TIMER_MEASURE,
	LOG_TYPE_AUTH,
	LOG_TYPE_OTHER
};


enum{
	LOG_ACTION_LOAD_PROGROM = 1,
	LOG_ACTION_FILE_READ,
	LOG_ACTION_FILE_WRITE,
	LOG_ACTION_NETWORK_SEND,
	LOG_ACTION_NETWORK_RECEIVE,
	LOG_ACTION_DEVICE_ACCESS,
	LOG_ACTION_SCHEDULE_CHECK,
	LOG_ACTION_OTHER
};

enum{
	LOG_RESULT_REJECT = 0,
	LOG_RESULT_PASS,
	LOG_RESULT_OTHER
};


enum{
	LOG_LEVEL_DEBUG = 1,
	LOG_LEVEL_NORMAL,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_FATAL
};


//文件、网络、设备,内核、内核模块、内核数据、进程、共享库、进程数据、
enum{
	MEASURE_TAGERT_TYPE_FILE = 1,
	MEASURE_TAGERT_TYPE_NETWORK,
	MEASURE_TAGERT_TYPE_DEVICE,
	MEASURE_TAGERT_TYPE_OTHER,
	MEASURE_TAGERT_KERNEL,
	MEASURE_TAGERT_KERNEL_MODULE,
	MEASURE_TAGERT_KERNEL_DATA,
	MEASURE_TAGERT_PROCESS,
	MEASURE_TAGERT_SHALL_LIB,
	MEASURE_TAGERT_PROCESS_DATA,
};


struct long_info{
	unsigned long id;
	long long time;
	int category;
	int type;
	const char *module;
	const char *source;
	//
	int action;
	int result;
	int level;
	const char *process;
	const char *program;
	unsigned pid;
	unsigned uid;
	//
	const char *exec;
	const char *object_type;
	const char *object;
	const char *measure_name;
	int measure_target_type;
	const char *measure_target;
	const char *measure_content;
	const char *message;
};

struct long_param{
	int category;
	int type;
	const char *module;
	const char *source;
	int action;
	int result;
	int level;
	const char *exec;
	const char *object;
	const char *measure_name;
	int measure_target_type;
	const char *measure_target;
	const char *measure_content;
	const char *message;
};
int log_out(const struct long_param *param);
int log_out_test(int param);

struct tpcm_audit_log {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	ktime_t t_sec;
#else
	time_t t_sec;
#endif
	int type;
	int operate;
	int result;
};

int keraudit_log(int type, int operate, int result, struct sec_domain *sec_d, unsigned int user, int pid);
int keraudit_log_from_tpcm(const struct tpcm_audit_log *tpcm_audit, struct sec_domain *sec_d, unsigned int user, int pid);

#endif /* SRC_LOG_LOG_H_ */
