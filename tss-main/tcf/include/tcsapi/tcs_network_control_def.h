/*
 * @Description: 
 * @Author: huatai
 * @Date: 2022-05-20 13:55:10
 * @LastEditTime: 2022-05-20 14:57:45
 * @LastEditors: huatai
 */
#ifndef TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_DEF_H_
#define TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_DEF_H_
#include <stdint.h>
#include "tcs_constant.h"
#define FILE_NETWORK_POLICY_PATH 			HTTC_TSS_CONFIG_PATH"network_config.data"

#pragma pack(push, 1)


#define NET_CONF_BLACK_FLAGS  0x00000001  /* 黑名单标记 */
#define NET_CONF_PORT_FLAGS   0x00000002  /* 端口标记 */
#define NET_CONF_TCP_FLAGS    0x00000004  /* TCP标记 */
#define NET_CONF_UDP_FLAGS    0x00000008  /* UDP标记 */

 struct ip_config
{
	uint32_t be_id;        /* 用户配置ID */
	uint32_t be_from;      /* 用户开始端口或IP */
	uint32_t be_to;        /* 用户结束端口或IP */ 
	uint32_t be_status;     /* 0bit--黑白名单标记位; 1bit--端口策略; 2bit--TCP标记; 3bit--UDP标记 */
};

 struct network_config_item
{
	uint32_t be_port_sw;       /* 网络过滤开关 0--关闭 1--打开 */
	uint32_t be_total_num;     /* 配置策略总数 */
	struct ip_config item[0];
};

struct network_control_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// network_config_item array
};
#pragma pack(pop)


#endif /* TRUNK_INCLUDE_TCSAPI_TCS_NETWORK_CONTROL_DEF_H_ */
