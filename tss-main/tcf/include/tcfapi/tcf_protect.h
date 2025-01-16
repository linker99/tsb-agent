/*
 * tcf_protect.h
 *
 *  Created on: 2021年5月12日
 *      Author: wangtao
 */

#ifndef INCLUDE_TCFAPI_TCF_PROTECT_H_
#define INCLUDE_TCFAPI_TCF_PROTECT_H_
struct ptrace_protect_update;
struct ptrace_protect_user{
	int is_ptrace_protect;//是否开启进程跟踪保护
	unsigned int ptracer_number;//例外进程（可跟踪其它进程的进程）数量，通过进程身份鉴定）
	unsigned int non_tracee_number;//不可被跟踪的进程数量（即使跟踪者是例外进程也不可跟踪这些进程）
	char **ptracer_names;//进程的名字列表
	char **non_tracee_names;//进程的名字列表
	//struct process_name[ptracer_number + untraceable_number] 4 byte align
};

/*
 * 	准备更新动态度量策略
 */
int tcf_prepare_ptrace_protect_policy(
		struct ptrace_protect_user *items,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct ptrace_protect_update **update,int *olen);

int tcf_update_ptrace_protect_policy(struct ptrace_protect_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * 读取进程跟踪防护策略
 */
int tcf_get_ptrace_protect_policy(struct ptrace_protect_user **ptrace_protect);

/*
 * 释放进程跟踪防护策略内存
 */
void tcf_free_ptrace_protect_policy(struct ptrace_protect_user *ptrace_protect);
#endif /* INCLUDE_TCFAPI_TCF_PROTECT_H_ */
