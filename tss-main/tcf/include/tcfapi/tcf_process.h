/*
 * process.h
 *
 *  Created on: 2021年3月10日
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_PROCESS_H_
#define TCFAPI_TCF_PROCESS_H_
#include <stdint.h>
#include "tcsapi/tcs_process_def.h"
struct process_identity_update;
struct process_role_update;

struct process_role_user{
	unsigned int member_number;
	unsigned char *name;
	unsigned char **members;
};

struct process_identity_user{
	unsigned char *name;
	uint32_t hash_length;
	int specific_libs;
	int lib_number;
	unsigned char *hash;
};

/*
 * 准备更新进程身份
 */
int tcf_prepare_update_process_identity(
		struct process_identity_user *process_ids,int id_number,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct process_identity_update **update,int *olen
		);

/*
 * 更新进程身份。
 * 设置、增加、删除、修改。
 */
int tcf_update_process_identity(
		struct process_identity_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);

/*
 * 读取全部进程身份
 */
int tcf_get_process_ids(struct process_identity_user **ids,int *num);

/*
 * 读取指定进程身份
 */
int tcf_get_process_id(const unsigned char *name,struct process_identity_user **ids,int *num);

/*
 * 释放进程身份内存
 */
void tcf_free_process_ids(struct process_identity_user *ids,int num);
/*
 * 准备更新进程角色
 */
int tcf_prepare_update_process_roles(
		struct process_role_user *roles,int roles_number,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct process_role_update **update,int *olen
		);

/*
 * 更新进程角色库。
 * 设置、增加、删除、修改。
 */
int tcf_update_process_roles(struct process_role_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);

/*
 * 读取全部进程角色
 */
int tcf_get_process_roles(struct process_role_user **roles,int *num);


/*
 * 读取指定进程角色
 * 返回最多一个
 */
int tcf_get_process_role(const unsigned char *name,struct process_role_user **roles);
/*
 * 释放进程角色内存
 */
void tcf_free_process_roles(struct process_role_user *roles,int num);

#endif /* TCFAPI_TCF_PROCESS_H_ */
