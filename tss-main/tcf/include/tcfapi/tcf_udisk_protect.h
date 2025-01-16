/*
 * @Description: 
 * @Author: huatai
 * @Date: 2022-05-20 13:55:11
 * @LastEditTime: 2022-06-08 10:34:12
 * @LastEditors: huatai
 */
#ifndef TRUNK_INCLUDE_TCFAPI_TCF_UDISK_PROTECT_H_
#define TRUNK_INCLUDE_TCFAPI_TCF_UDISK_PROTECT_H_

#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_udisk_protect_def.h"



//直接导出tsb功能
#include "../tsbapi/tsb_udisk.h"
/*
 * 	读取光驱保护策略
 */

int tcf_get_udisk_protect_policy(struct udisk_conf_item **references, unsigned int *inout_num);//proc 导出


/*
 * 	更新光驱保护策略
 * 	支持设置。
 */



int tcf_update_udisk_protect_policy(
		struct udisk_protect_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth);
/**/
int tcf_prepare_update_udisk_protect_policy(
		struct udisk_conf_item *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct udisk_protect_update **buffer,unsigned int *prepare_size);
/*释放*/

void tcf_free_udisk_protect_policy(struct udisk_conf_item * pp);		
#endif /* TRUNK_INCLUDE_TCFAPI_TCF_DEV_PROTECT_H_ */
