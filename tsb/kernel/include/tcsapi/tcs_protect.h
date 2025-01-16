

#ifndef INCLUDE_TCSAPI_TCS_PROTECT_H_
#define INCLUDE_TCSAPI_TCS_PROTECT_H_

#include "tcs_constant.h"
#include "tcs_protect_def.h"

#pragma pack(push, 1)
struct ptrace_protect_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct ptrace_protect data[1];// struct process_identity array,align on 4 byte
};
#pragma pack(pop)

/*
 * 更新进程跟踪防护策略。
 * 设置
 */
int tcs_update_ptrace_protect_policy(struct ptrace_protect_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * 读取进程跟踪防护策略
 */
int tcs_get_ptrace_protect_policy(struct ptrace_protect **ptrace_protect,int *length);

#endif /* INCLUDE_TCSAPI_TCS_PROTECT_H_ */
