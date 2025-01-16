/*
 * policy.h
 *
 *  Created on: 2021年1月12日
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_POLICY_H_
#define TCFAPI_TCF_POLICY_H_
#include "../tcsapi/tcs_policy_def.h"



//通用控制策略管理
/*
 * 设置全局控制策略
 * uid为空时轮询所有管理者证书
 */
int tcf_set_global_control_policy(
		struct global_control_policy_update *data,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);//proc导出，需先设置认证

/*
 * 获取全局控制策略
 */

int tcf_get_global_control_policy(struct global_control_policy *policy);//proc 导出

/*
 * 获取策略报告
 * （可验签的）
 */

int tcf_get_policy_report(struct policy_report *policy_report,uint64_t nonce);//proc 导出


#endif /* TCFAPI_TCF_POLICY_H_ */
