#include "tcfapi/tcf_license.h"
#include <httcutils/debug.h>
#include "tcsapi/tcs_error.h"
#include "tsbapi/tsb_admin.h"
#include "httcutils/sys.h"
#include <stdio.h>
#include <tcfapi/tcf_error.h>
/*
 * 	生成License请求
 * 	基于输入参数，生成License请求，License请求发送给TPCM生成厂商进行授权
 * 	部分TPCM自带永久许可授权，不需要进行许可授权。
 */
int tcf_generate_license_request(struct license_req *req,const struct license_param *param){
	int ret = 0;

	ret = tcs_generate_license_request(req, param);
	if(ret != 0){
		httc_util_pr_error("%s : %d  : tcf generate license request \n", __func__, __LINE__);
		goto out;
	}
out:
	return ret;
}

/*
 * 	导入License
 * 	将TPCM生产厂商授权的License，导入到TPCM之中。
 *	部分TPCM自带永久许可授权，不需要进行许可授权。
 */
int tcf_import_license(struct license *license){
	int ret = 0;

	ret = tcs_import_license(license);
	if(ret != 0){
		httc_util_pr_error("%s : %d  :  tcf import license \n", __func__, __LINE__);
		goto out;
	}
out:
	return ret;
}

//int tcf_upgrade_license(struct license *license);

/*
 * 	获取License状态
 * 	获取License状态，如果是试用则返回剩余天数。
 */
int tcf_get_license_status(int *status,int *left){
	int ret = 0;

	ret = tcs_get_license_status(status, left);
	if(ret != 0){
		httc_util_pr_error("%s : %d  : tcf get license status \n", __func__, __LINE__);
		goto out;
	}
out:
	return ret;
}//proc导出

/*
 * 	获取License信息
 */
int tcf_get_license_info(int *status, uint64_t *deadline)
{
	int ret = 0;

	ret = tcs_get_license_info(status, deadline);
	if(ret != 0){
		httc_util_pr_error("%s : %d  : tcf get license info \n", __func__, __LINE__);
		goto out;
	}
out:
	return ret;
}

int tcf_get_license_entity(struct license_entity *data, int *num)
{
	int ret = 0;

	ret = tcs_get_license_entity(data, num);
	if(ret != 0){
		httc_util_pr_error("%s : %d  : tcf get license entity \n", __func__, __LINE__);
		goto out;
	}
out:
	return ret;
}

/*
 * 	重置试用期
 * 	重新开始试用期计时，同时将清除全部数据。
 */
int tcf_reset_test_license()
{
	int ret = 0;

	ret = tcs_reset_test_license();
	if(ret != 0){
		httc_util_pr_error(" tcf reset test license error : %d \n",  ret);
		goto out;
	}
	if (httc_util_rm (HTTC_TSB_CONFIG_PATH"*")){
		httc_util_pr_error ("httc_util_rm %s* error\n", HTTC_TSB_CONFIG_PATH);
		ret = TCF_ERR_FILE;
		goto out;
	}
	if (0 != (ret = tsb_rotate_log_file ())){
		if(ret == -1){
			httc_util_pr_info ("tsb_rotate_log_file: %d\n", ret);
			}
		ret = TCF_SUCCESS;
		goto out;
	}
out:

	return ret;
}
