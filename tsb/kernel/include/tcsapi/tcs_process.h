

#ifndef TCSAPI_TCS_PROCESS_H_
#define TCSAPI_TCS_PROCESS_H_
#include "tcs_constant.h"
#include "tcs_process_def.h"
#pragma pack(push, 1)

struct process_role_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// struct process_role array,align on 4 byte
};


struct process_identity_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// struct process_identity array,align on 4 byte
};
#pragma pack(pop)





/*
 * 更新进程身份。
 * 设置、增加、删除、修改。
 */
int tcs_update_process_identity(
		struct process_identity_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * 读取全部进程身份
 */
int tcs_get_process_ids(struct process_identity **ids,int *num,int *length);




/*
 * 更新进程角色库。
 * 设置、增加、删除、修改。
 */
int tcs_update_process_roles(struct process_role_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * 读取全部进程角色
 */
int tcs_get_process_roles(struct process_role **roles,int *num,int *length);



#endif /* TCSAPI_TCS_PROCESS_H_ */
