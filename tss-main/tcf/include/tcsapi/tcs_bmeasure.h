/*
 * bmeasure.h
 *
 *  Created on: 2021年3月9日
 *      Author: wangtao
 */

#ifndef TCSAPI_TCS_BMEASURE_H_
#define TCSAPI_TCS_BMEASURE_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#include "tcs_kernel_def.h"

#pragma pack(push, 1)

struct boot_measure_record{
	uint64_t be_measure_time;
	uint32_t be_result;
	uint16_t be_hash_length;
	uint16_t be_name_length;
	uint16_t be_stage;
	unsigned char data[0];//hash + name
};

struct boot_ref_item{
	uint16_t be_hash_length;
	uint16_t be_flags;//开关(不是删除)，是否控制
	uint16_t be_name_length;
	uint16_t be_hash_number;//支持多版本HASH
	uint16_t be_stage;
	uint16_t be_extend_size;
	unsigned char data[0];	//hash + extend_data + name
};

struct boot_references_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//boot_ref_item array,every item 4 byte align
};
#pragma pack(pop)


enum{
	BOOT_REFERENCE_FLAG_ENABLE = 0,
	BOOT_REFERENCE_FLAG_CONTROL,
};

unsigned char *boot_ref_name(struct boot_ref_item *boot_ref_item);
unsigned char *boot_extend_data(struct boot_ref_item *boot_ref);
unsigned char *boot_hash(struct boot_ref_item *boot_ref);
struct boot_ref_item *boot_ref_next(struct boot_ref_item *boot_ref);






// boot measure reference interface
/*
 * 	更新启动度量基准库
 * 	设置。
 */

int tcs_update_boot_measure_references(struct boot_references_update *references,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	获取启动度量基准库
 */
int tcs_get_boot_measure_references(struct boot_ref_item **references,int *num,int *length);//proc 导出


/*
 * 	获取启动度量记录（采集值）
 */

int tcs_get_boot_measure_records(struct  boot_measure_record  **boot_records,int *num,int *length);

/*
 * 	启动度量
 */

int tcs_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen);

/*
 *	简易启动度量
 */
int tcs_simple_boot_measure (uint32_t stage, uint8_t* digest, uint8_t *obj, uint32_t objLen);



#endif /* TCSAPI_TCS_BMEASURE_H_ */
