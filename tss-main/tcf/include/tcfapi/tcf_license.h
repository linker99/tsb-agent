/*
 * license.h
 *
 *  Created on: 2021年1月22日
 *      Author: wangtao
 */

#ifndef TCSAPI_LICENSE_H_
#define TCSAPI_LICENSE_H_

#include "../tcsapi/tcs_license.h"

/*
 * 	生成License请求
 * 	基于输入参数，生成License请求，License请求发送给TPCM生成厂商进行授权
 * 	部分TPCM自带永久许可授权，不需要进行许可授权。
 */
int tcf_generate_license_request(struct license_req *req,const struct license_param *param);

/*
 * 	导入License
 * 	将TPCM生产厂商授权的License，导入到TPCM之中。
 *	部分TPCM自带永久许可授权，不需要进行许可授权。
 */
int tcf_import_license(struct license *license);

//int tcs_upgrade_license(struct license *license);
/*
 * 	获取License状态
 * 	获取License状态，如果是试用则返回剩余天数。
 */
int tcf_get_license_status(int *status,int *left);


/*
 * 	获取License信息
 */
int tcf_get_license_info(int *status, uint64_t *deadline);


int tcf_get_license_entity(struct license_entity *data, int *num);

/*
 * 	重置试用期
 * 	重新开始试用期计时，同时将清除全部数据。
 */
int tcf_reset_test_license(void);


#endif /* TCSAPI_LICENSE_H_ */
