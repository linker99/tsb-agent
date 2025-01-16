

#ifndef INCLUDE_TCSAPI_TCS_TNC_H_
#define INCLUDE_TCSAPI_TCS_TNC_H_
#include "tcs_tnc_def.h"

/*
 * 更新可信网络连接策略。
 * 只有设置
 */
int tcs_update_tnc_policy(struct tnc_policy_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * 读取可信网络连接策略
 */
int tcs_get_tnc_policy(struct tnc_policy **tnc_policy,int *length);

#endif /* INCLUDE_TCSAPI_TCS_TNC_H_ */
