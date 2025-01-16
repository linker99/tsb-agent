/*
 * config.h
 *
 *  Created on: 2021年1月21日
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_CONFIG_H_
#define TCFAPI_TCF_CONFIG_H_

#include <stdint.h>
#include "tcf_config_def.h"

/*
 * 	设置日志配置
 */
int tcf_set_log_config(const struct log_config *config, uint64_t version);//可proc控制，查看
/*
 * 	读取日志配置
 */
int tcf_get_log_config(struct log_config *config);//可proc控制，查看

/*
 * 设置通知缓存条数(取值1000-2000)
 */
int tcf_set_notice_cache_number(int num, uint64_t version);

/*
 * 	读取通知缓存条数
 */
int tcf_get_notice_cache_number(int *num);
#endif /* TCFAPI_TCF_CONFIG_H_ */
