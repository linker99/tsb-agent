#include <stdio.h>

#include <httcutils/debug.h>
#include <httcutils/convert.h>
#include "tcfapi/tcf_policy.h"
#include "tcsapi/tcs_policy.h"
#include "tsbapi/tsb_admin.h"
#include "tutils.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"


//通用控制策略管理
/*
 * 设置全局控制策略
 * uid为空时轮询所有管理者证书
 */
int tcf_set_global_control_policy(
		struct global_control_policy_update *data,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth){

	int ret = 0;

	ret = tcs_set_global_control_policy(data, uid, cert_type, auth_length, auth);
	if(ret) return ret;

	if ((ret = tsb_set_global_control_policy((const char *)&(data->policy),sizeof(struct global_control_policy)))){
		if(ret == -1){
			httc_util_pr_info ("tsb_set_global_control_policy : %d(0x%x)\n", ret, ret);
			}
		ret = TCF_SUCCESS;
	}

	httc_write_version_notices (ntohll (data->be_replay_counter), POLICY_TYPE_GLOBAL_CONTROL_POLICY);

	return ret;

}//proc导出，需先设置认证

/*
 * 获取全局控制策略
 */

int tcf_get_global_control_policy(struct global_control_policy *policy){
	return tcs_get_global_control_policy(policy);
}//proc 导出

/*
 * 获取策略报告
 * （可验签的）
 */

int tcf_get_policy_report(struct policy_report *policy_report,uint64_t nonce){
	return tcs_get_policy_report(policy_report, nonce);
}//proc 导出



