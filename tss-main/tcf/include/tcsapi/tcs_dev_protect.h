/*
 * tcs_dev_protect.h
 *
 *  Created on: 2022年5月10日
 *      Author: wangtao
 */

#ifndef TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_H_
#define TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_H_


#include "tcs_dev_protect_def.h"

/*
 * 	读取光驱保护策略
 */
int tcs_get_cdrom_protect_policy(struct cdrom_protect_item **items, int *num, int *length);//proc 导出



/*
 * 	更新文件保护策略
 * 	支持设置。
 */

int tcs_update_cdrom_protect_policy(
		struct cdrom_protect_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);


#endif /* TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_H_ */
