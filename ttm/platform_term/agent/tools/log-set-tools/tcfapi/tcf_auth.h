/*
 * auth.h
 *
 *  Created on: 2021年1月28日
 *      Author: wangtao
 */

#ifndef TCFAPI_TCF_AUTH_H_
#define TCFAPI_TCF_AUTH_H_
#include <stdint.h>
#include "../tcsapi/tcs_auth_def.h"

struct admin_cert_info{
	uint32_t is_root;
	uint32_t cert_type;
	uint32_t cert_len;
	unsigned char name[TPCM_UID_MAX_LENGTH];
	unsigned char data[MAX_CERT_SIZE];
};

//管理员证书
/*
 * 	设置根管理员证书
 * 	将证书所有者设置为根管理员
 * 	首次设置无需认证，再次设置需认证
 * 	使用之前的根管理员证书进行认证，
 */
int tcf_set_admin_cert(struct admin_cert_update *update,
									int cert_type,
								    int auth_length,unsigned char *auth
						);


/*
 * 	授予二级管理员角色
 * 	授予二级管理员角色给证书所有者，证书所有者成为二级管理员
 *	调用者需认证为根管理员
 */

int tcf_grant_admin_role(struct admin_cert_update *cert_update,
						int auth_type,
						int auth_length,unsigned char *auth);
/*
 *	删除二级管理员。
 * 	将证书所有者从二级管理员中删除
 * 	调用者需认证为根管理员
 * 	删除时可不填写证书得数据部分。
 */

int tcf_remove_admin_role(struct admin_cert_update *cert_update,
		int auth_type,
		int auth_length,unsigned char *auth);

/*
 *	读取管理员证书列表
 *	返回全部管理员证书，如果是密码认证得管理员证书，不返回密码数据。
 */
int tcf_get_admin_list(struct admin_cert_info **list,
		int *list_size);

/*
 * 	释放管理员证书列表内存
 *	释放由读取管理员证书列表返回的内存。
 */
int tcf_free_admin_list(struct admin_cert_info *list,
		int list_size);

/*
 * 设置TPCM管理认证策略
 */
int tcf_set_admin_auth_policies(struct admin_auth_policy_update *update,
			const char *uid, int auth_type,
				int auth_length,unsigned char *auth);
/*
 * 获取TPCM管理认证策略
 */
int tcf_get_admin_auth_policies(struct admin_auth_policy **list,
		int *list_size);

#endif /* TCFAPI_TCF_AUTH_H_ */
