

#ifndef TCFAPI_TCF_DMEASURE_H_
#define TCFAPI_TCF_DMEASURE_H_
#include <stdint.h>
#define MAX_DMEASURE_HASH_VERSION_NUMBER 8

struct dmeasure_policy_update;
struct dmeasure_reference_update;
struct dmeasure_process_policy_update;

struct dmeasure_policy_item_user{
	char *name;
	int type;
	int interval_milli;
};

struct dmeasure_process_item_user{
	uint8_t object_id_type;//客体标识类型全路径、进程名、HASH
	uint8_t sub_process_mode;//子进程，度量、不度量、默认（按全局策略控制）
	uint8_t old_process_mode;//策略生效前已启动的进程，度量、不度量、默认（按全局策略控制）
	uint8_t share_lib_mode;//共享库，度量、不度量、默认（按全局策略控制）
	uint32_t measure_interval;//度量间隔毫秒，0为默认（按全局策略控制）
	uint16_t object_id_length; //客体长度
	char *object_id;//客体标识（全路径、进程名、HASH）
};

//进程动态度量
struct dmeasure_reference_item_user{
	int hash_length;//
	int hash_number;//support multi version(用于代码段可变)
	char  *hash_buffer;//length=hash_length  * hash_number
	char *name;//hash+name
};




/*
 * 	准备更新动态度量策略
 */
int tcf_prepare_update_dmeasure_policy(
		struct dmeasure_policy_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_policy_update **policy,int *olen);

/*
 * 	准备更新进程动态度量策略
 */
int tcf_prepare_update_dmeasure_process_policy(
		struct dmeasure_process_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_process_policy_update **policy,int *olen);

/*
 * 	更新动态度量策略
 * 	设置
 */

int tcf_update_dmeasure_policy(struct dmeasure_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	更新动态度量策略
 * 	设置、增加、删除。
 */

int tcf_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_process_policy(struct dmeasure_process_item_user **policy,int *item_count);//proc 导出


/*
 * 	释放进程动态度量策略内存
 */
void tcf_free_dmeasure_process_policy(struct dmeasure_process_item_user *policy,int item_count);//proc 导出

/*
 * 	获取动态度量策略
 */
int tcf_get_dmeasure_policy(struct dmeasure_policy_item_user **policy,int *item_count);//proc 导出

/*
 * 	释放动态度量策略内存
 */
void tcf_free_dmeasure_policy(struct dmeasure_policy_item_user *policy,int item_count);//proc 导出

/*
 * 	准备动态度量更新
 */
int tcf_prepare_update_dmeasure_reference(
		struct dmeasure_reference_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_reference_update **reference,int *olen);
/*
 * 	设置动态度量基准值
 */
int tcf_update_dmeasure_reference(struct dmeasure_reference_update *reference);

/*
* 	设置动态度量基准值，带认证
 */
int tcf_update_dmeasure_reference_auth(struct dmeasure_reference_update *reference,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	获取动态度量基准库
 */
int tcf_get_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count);//proc 导出

/*
 * 	释放动态度量基准值内存
 */
void tcf_free_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count);//proc 导出

#endif /* TCFAPI_TCF_DMEASURE_H_ */
