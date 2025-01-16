/*
 * tcs_dev_protect.h
 *
 *  Created on: 2022年5月10日
 *      Author: wangtao
 */

#ifndef TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_H_
#define TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_H_


#include "tcs_network_control_def.h"

/*
 * 	读取网络保护策略
 */
int tcs_get_network_control_policy(struct network_config_item **items, int *num, int *length);//proc 导出



/*
 * 	更新光驱保护策略
 * 	支持设置。
 */


int tcs_update_network_control_policy(
		struct network_control_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);


#endif /* TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_H_ */
