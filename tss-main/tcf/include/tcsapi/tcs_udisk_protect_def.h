/*
 * @Description: 
 * @Author: huatai
 * @Date: 2022-05-20 13:55:10
 * @LastEditTime: 2022-05-20 14:57:45
 * @LastEditors: huatai
 */
#ifndef TRUNK_INCLUDE_TCSAPI_TCS_UDISK_PROTECT_DEF_H_
#define TRUNK_INCLUDE_TCSAPI_TCS_UDISK_PROTECT_DEF_H_
#include <stdint.h>
#include "tcs_constant.h"
#define FILE_UDISK_POLICY_PATH 			HTTC_TSS_CONFIG_PATH"udisk_config.data"

#pragma pack(push, 1)
#define __GUID_LENGTH (48)

struct udisk_conf_item
{
 uint32_t access_ctrl;            /* 1--read only, 2-- read write */
 char guid[__GUID_LENGTH];     /* U盘guid  */
} __attribute__ ((packed));

struct udisk_protect_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// udisk_conf array
};
#pragma pack(pop)


#endif /* TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_DEF_H_ */
