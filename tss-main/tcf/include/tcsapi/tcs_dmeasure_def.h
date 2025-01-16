/*
 * tcs_dmeasure_def.h
 *
 *  Created on: 2021年4月14日
 *      Author: wangtao
 */

#ifndef TCSAPI_TCS_DMEASURE_DEF_H_
#define TCSAPI_TCS_DMEASURE_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#define MAX_DMEASURE_HASH_VERSION_NUMBER 8
#define TPCM_DMEASURE_OBJECT_SIZE	32
#pragma pack(push, 1)

struct dmeasure_policy_item{
	uint32_t be_type;
	uint32_t be_interval_milli;
	unsigned char object[TPCM_DMEASURE_OBJECT_SIZE];//name
};

struct dmeasure_process_item{
	uint8_t object_id_type;//客体标识类型全路径、进程名、HASH
	uint8_t sub_process_mode;//子进程，度量、不度量、默认（按全局策略控制）
	uint8_t old_process_mode;//策略生效前已启动的进程，度量、不度量、默认（按全局策略控制）
	uint8_t share_lib_mode;;//共享库，度量、不度量、默认（按全局策略控制）
	uint32_t be_measure_interval;//度量间隔毫秒，0为默认（按全局策略控制）
	uint16_t be_object_id_length; //客体长度
	unsigned char object_id[0];//客体标识（全路径、进程名、HASH）
};

#pragma pack(pop)

#endif /* TCSAPI_TCS_DMEASURE_DEF_H_ */
