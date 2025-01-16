/*
 * dmeasure.h
 *
 *  Created on: 2021年3月9日
 *      Author: wangtao
 */

#ifndef TCSAPI_TCS_DMEASURE_H_
#define TCSAPI_TCS_DMEASURE_H_
#include "tcs_dmeasure_def.h"

#pragma pack(push, 1)

struct dmeasure_process_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//process_dmesaure_item array,every item 4 byte align
};

struct dmeasure_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//dmeasure_item array,every item 4 byte align
};


struct dmeasure_reference_item{
	uint32_t be_hash_length;//
	uint32_t be_hash_number;//support multi version(用于代码段可变)
	uint32_t be_name_length;
	unsigned char data[0];//hash+name
};


struct dmeasure_reference_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//dmeasure_item array,every item 4 byte align
};

#pragma pack(pop)

//动态度量策略管理
/*
 * 	更新动态度量策略
 * 	设置、增加、删除。
 */

int tcs_update_dmeasure_policy(struct dmeasure_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);

//动态度量策略管理
/*
 * 	更新进程动态度量策略
 * 	设置、增加、删除。
 */

int tcs_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	获取动态度量策略
 */
int tcs_get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length);//proc 导出


/*
 * 	获取进程动态度量策略
 */
int tcs_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length);//proc 导出


/*
 * 	设置动态度量基准值
 */
int tcs_update_dmeasure_reference(struct dmeasure_reference_update *reference);

/*
* 	设置动态度量基准值，带认证
 */
int tcs_update_dmeasure_reference_auth(struct dmeasure_reference_update *reference,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	获取动态度量基准库
 */
int tcs_get_dmeasure_reference(struct dmeasure_reference_item **references,int *item_count,int *length);//proc 导出



#endif /* TCSAPI_TCS_DMEASURE_H_ */
