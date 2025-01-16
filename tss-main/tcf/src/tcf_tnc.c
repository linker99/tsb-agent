#include "tcfapi/tcf_tnc.h"
#include "tcfapi/tcf_error.h"

#include "tcsapi/tcs_tnc.h"
#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_notice.h"
#include "httcutils/convert.h"
#include "httcutils/debug.h"
#include "tutils.h"



/*
 * 更新可信网络连接策略。
 * 只有设置
 */
int tcf_update_tnc_policy(struct tnc_policy_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth){

		int ret = 0;

		ret = tcs_update_tnc_policy(update,uid,cert_type,auth_length,auth);
		if(ret) return ret;

		if (0 != (ret = tsb_set_tnc_policy((const char *)update->policy))){
			if(ret == -1){
				httc_util_pr_info ("tsb_set_tnc_policy : %d(0x%x)\n", ret, ret);
				}
			ret = TCF_SUCCESS;
		}

		httc_write_version_notices (ntohll (update->be_replay_counter), POLICY_TYPE_TNC);
		return ret;
}

/*
 * 读取可信网络连接策略
 */
int tcf_get_tnc_policy(struct tnc_policy **tnc_policy,int *length){
	return tcs_get_tnc_policy(tnc_policy,length);
}

