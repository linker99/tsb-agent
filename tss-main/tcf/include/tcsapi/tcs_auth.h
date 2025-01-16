/*
 * auth.h
 *
 *  Created on: 2021年1月28日
 *      Author: wangtao
 */

#ifndef TCSAPI_AUTH_H_
#define TCSAPI_AUTH_H_
#include "tcs_auth_def.h"
//
//struct auth_policy{
//	unsigned int policy_flags;
//	unsigned char *process_or_role;
//	unsigned int *user_or_group;
//	unsigned char *password;
//};
//管理员证书
/*
 * 	设置根管理员证书
 * 	将证书所有者设置为根管理员
 * 	首次设置无需认证，再次设置需认证
 * 	使用之前的根管理员证书进行认证，
 */
int tcs_set_admin_cert(struct admin_cert_update *update,
									int cert_type,
								    int auth_length,unsigned char *auth
						);


/*
 * 	授予二级管理员角色
 * 	授予二级管理员角色给证书所有者，证书所有者成为二级管理员
 *	调用者需认证为根管理员
 */

int tcs_grant_admin_role(struct admin_cert_update *cert_update,
						int cert_type,
						int auth_length,unsigned char *auth);
/*
 *	删除二级管理员。
 * 	将证书所有者从二级管理员中删除
 * 	调用者需认证为根管理员
 * 	删除时可不填写证书得数据部分。
 */

int tcs_remove_admin_role(struct admin_cert_update *cert_update,
		int cert_type,
		int auth_length,unsigned char *auth);


/*
 *	读取管理员证书列表
 *	返回全部管理员证书，如果是密码认证得管理员证书，不返回密码数据。
 */
int tcs_get_admin_list(struct admin_cert_item **list,
		int *num);

/*
 * 设置TPCM管理认证策略
 */
int tcs_set_admin_auth_policies(struct admin_auth_policy_update *update,
				const char *uid, int cert_type, int auth_length,unsigned char *auth);
/*
 * 获取TPCM管理认证策略
 */
int tcs_get_admin_auth_policies(struct admin_auth_policy **list,
		int *num);

/*
 * 添加根证书
 */
int tcs_set_root_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						);

/*
 * 更新根证书
 */
int tcs_update_root_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						);

/*
 * 查询根证书
 */
int tcs_query_root_cert(unsigned int *result);

/*
 * 更新二级证书
 */
int tcs_update_role_cert(struct root_cert_update *update, const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						);

/*
 * 删除二级证书
 */
int tcs_delete_role_cert(const char *uid,
									int cert_type,
								    int auth_length,unsigned char *auth
						);

/*
 * 生成秘钥对
 */
int tcs_generate_key (char * uid, uint32_t cert_type,uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key );

/*
 * 查询公钥
 */
int tcs_get_index_pubkey (char * uid,uint32_t cert_type, uint32_t auth_length,unsigned char *auth,uint32_t index,char * id,char *key );


/*
 * 查询ek公钥
 */
int tcs_get_ek_pubkey (char * uid, uint32_t cert_type,uint32_t auth_length,unsigned char *auth,char * id,char *key );


/*
 * 导入 ek 证书
 */
int tcs_import_ek(struct root_cert_update *update,
			   const char *uid, int cert_type, int auth_length, unsigned char *auth);
/*
 * 验证 ek 证书
 */			   
int tcs_verify_ek(struct root_cert_update *update,
			   const char *uid, int cert_type, int auth_length, unsigned char *auth, int *result);
/*
 * 获取 ek 证书
 */
int tcs_get_ek(struct root_cert_item *update,
			   const char *uid, int cert_type, int auth_length, unsigned char *auth);


/*
 * 更新根证书
 * 包含 证书虚拟地址版本 
 */
int tcs_update_root_cert_vir (struct root_cert_update_vir *update, const char *uid,int cert_type,int auth_length,unsigned char *auth,unsigned char *cert_auth);



#endif /* TCSAPI_AUTH_H_ */
