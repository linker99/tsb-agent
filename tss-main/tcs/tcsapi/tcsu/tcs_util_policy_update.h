/*
 * @Description: 
 * @Author: huatai
 * @Date: 2022-04-01 16:48:34
 * @LastEditTime: 2022-04-01 16:55:58
 * @LastEditors: huatai
 */
#ifndef __TCS_UTIL_POLICY_UPDATE__
#define __TCS_UTIL_POLICY_UPDATE__

#include "tcs_attest_def.h"
#include "tcs_auth_def.h"
#include "tcs_bmeasure.h"
#include "tcs_dmeasure.h"
#include "tcs_file_integrity.h"
#include "tcs_file_protect_def.h"
#include "tcs_dev_protect_def.h"
#include "tcs_udisk_protect_def.h"
#include "tcs_policy_def.h"
#include "tcs_process.h"
#include "tcs_protect.h"
#include "tcs_tnc_def.h"

enum TCS_POLICY_TYPE_ENUM{
	TCS_POLICY_TYPE_ADMIN_AUTH_CERT = 0,		//证书
	TCS_POLICY_TYPE_ADMIN_AUTH_POLICY,			//管理认证策略
	TCS_POLICY_TYPE_GLOBAL_CONTROL_POLICY,		//全局策略
	TCS_POLICY_TYPE_BMEASURE_REF,				//启动度量基准值
	TCS_POLICY_TYPE_DMEASURE,					//动态度量策略
	TCS_POLICY_TYPE_PROCESS_DMEASURE, 			//进程动态度量
	TCS_POLICY_TYPE_FILE_INTEGRITY, 			//白名单
	TCS_POLICY_TYPE_PROCESS_IDENTITY, 			//进程身份
	TCS_POLICY_TYPE_PROCESS_ROLE, 				//进程角色
	TCS_POLICY_TYPE_PTRACE_PROTECT, 			//进程跟踪
	TCS_POLICY_TYPE_TNC, 						//可信连接
	TCS_POLICY_TYPE_KEYTREE, 					//密钥树
	TCS_POLICY_TYPE_STORE,						//存储管理
	TCS_POLICY_TYPE_LOG, 						//审计策略
	TCS_POLICY_TYPE_NOTICE, 					//通知缓存
	TCS_POLICY_TYPE_CRITICAL_FILE_INTEGRITY,	//关键文件
	TCS_POLICY_TYPE_FILE_PROTECT,				//文件保护策略
	TCS_POLICIES_TYPE_MAX,
};

struct tcs_pik_para
{
unsigned char priv_key[32];
unsigned char pub_key[64];
};
int tcs_util_check_admin_cert_update (struct admin_cert_update *update);
int tcs_util_check_admin_auth_policy_update (struct admin_auth_policy_update *update);
//int tcs_util_check_boot_references_update (struct boot_references_update *update);
int tcs_util_check_dmeasure_policy_update (struct dmeasure_policy_update *update);
int tcs_util_check_dmeasure_process_policy_update (struct dmeasure_process_policy_update *update);
int tcs_util_check_file_integrity_update (struct file_integrity_update *update);
int tcs_util_check_critical_file_integrity_update (struct file_integrity_update *update);
int tcs_util_check_file_protect_update (struct file_protect_update *update);
int tcs_util_check_global_control_policy_update (struct global_control_policy_update *update);
int tcs_util_check_process_identity_update (struct process_identity_update *update);
int tcs_util_check_process_role_update (struct process_role_update *update);
int tcs_util_check_ptrace_protect_update (struct ptrace_protect_update *update);
int tcs_util_check_tnc_policy_update (struct tnc_policy_update *update);

/** 获取本地防重放计数 */
int tcs_util_read_replay_counter (uint64_t *replay_counter);

/** 修改本地防重放计数 */

int tcs_util_write_replay_counter (uint64_t counter);

/** 从本地获取策略版本 */
int tcs_util_read_policies_version (struct policy_version *version, int *num_inout);
/** 从本地写入策略版本 */
int tcs_util_write_policy_version (unsigned int id, uint64_t version);

/** 读取管理员证书列表，根据uid返回管理员证书*/
int tcs_util_get_cert_by_uid (const char *uid, struct admin_cert_item *cert);

/** 本地pik私钥数据签名 */
int tcs_util_pik_sign (const char *data, int datalen, char sign[DEFAULT_SIGNATURE_SIZE]);

/**纯软件版本证书验签 */
int tcs_util_verify_update (struct admin_cert_item *cert,
		int auth_type, int auth_length, unsigned char *auth, void *update, int update_size);

/** 本地写策略 */
int tcs_util_write_policy (const char* path, void *policy, int size, int num);

/** 本地读策略 */
int tcs_util_read_policy (const char* path, void **policy, int *size, int *num);


int tcs_util_get_pik_privkey (unsigned char priv[SM2_PRIVATE_KEY_SIZE]);

int tcs_util_inform_kernel_of_update (unsigned int command, void *policy, int size, int num);

int tcs_util_verify_update_by_admin_auth_policy(int id, int hash_len, unsigned char *hash);

/**本地计算策略的hash值 */
int tcs_util_calc_policy_hash (struct admin_auth_policy *policy, unsigned char *hash, int *hash_len);

int tcs_util_update_policy(	const char *uid,	int auth_type, int auth_length,unsigned char *auth, 
	void *data, int data_len, const char* path, void *policy, int policy_size,int num, int policy_type ,int action, uint64_t counter);

#endif	/** __TCS_UTIL_POLICY_UPDATE__ */

