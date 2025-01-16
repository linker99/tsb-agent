/*
 * config.h
 *
 *  Created on: 2021年1月21日
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_DEV_VERSION_H_
#define TCFAPI_TCF_DEV_VERSION_H_

#include <stdint.h>
#include "tcf_dev_version.h"

/*
 * 	设置cdrom版本号
 */
int tcf_set_cdrom_version(uint64_t version);
/*
 * 	获取cdrom版本号
 */
int tcf_get_cdrom_config(uint64_t *get_version);

/*
 * 	设置cdrom版本号
 */
int tcf_set_udisk_version(uint64_t version);
/*
 * 	获取cdrom版本号
 */
int tcf_get_udisk_config(uint64_t *get_version);

/*
 * 	设置file protect版本号
 */
int tcf_set_file_protect_version(uint64_t version);
/*
 * 	获取file protect版本号
 */
int tcf_get_file_protect_config(uint64_t *get_version);

/*
 * 	设置网络控制版本号
 */
int tcf_set_network_version(uint64_t version);
/*
 * 	获取网络控制版本号
 */
int tcf_set_network_version(uint64_t version);
#endif /* TCFAPI_TCF_DEV_VERSION_H_ */
