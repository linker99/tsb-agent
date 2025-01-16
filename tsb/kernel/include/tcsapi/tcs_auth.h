

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

#endif /* TCSAPI_AUTH_H_ */
