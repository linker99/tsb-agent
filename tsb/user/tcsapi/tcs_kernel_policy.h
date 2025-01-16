

#ifndef TCSAPI_TCS_KERNEL_POLICY_H_
#define TCSAPI_TCS_KERNEL_POLICY_H_

#include "tcs_process_def.h"
#include "tcs_policy_def.h"
#include "tcs_dmeasure_def.h"
#include "tcs_protect_def.h"
#include "tcs_tnc_def.h"

/*
 * 读取全部进程身份
 */
int tcsk_get_process_ids(struct process_identity **ids,int *num,int *length);

/*
 * 读取全部进程角色
 */
int tcsk_get_process_roles(struct process_role **roles,int *num,int *length);

/*
 * 获取全局控制策略
 */
int tcsk_get_global_control_policy(struct global_control_policy *policy);//proc 导出

/*
 * 	获取动态度量策略
 */
int tcsk_get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length);//proc 导出

/*
 * 	获取进程动态度量策略
 */
int tcsk_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length);//proc 导出

/*
 * 获取进程跟踪保护策略
 */	
int tcsk_get_ptrace_protect_policy(struct ptrace_protect **policy, int *length);//proc 导出

/*
 * 获取可信链接策略
 */
int tcsk_get_tnc_policy(struct tnc_policy **policy, int *length);//proc 导出

#endif /* TCSAPI_TCS_KERNEL_POLICY_H_ */
