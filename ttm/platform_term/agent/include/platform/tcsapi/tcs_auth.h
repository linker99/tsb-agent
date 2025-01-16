
#ifndef TCSAPI_AUTH_H_
#define TCSAPI_AUTH_H_
#include "tcs_auth_def.h"
 
//����Ա֤��
/*
 * 	���ø�����Ա֤��
 * 	��֤������������Ϊ������Ա
 * 	�״�����������֤���ٴ���������֤
 * 	ʹ��֮ǰ�ĸ�����Ա֤�������֤��
 */
int tcs_set_admin_cert(struct admin_cert_update *update,
									int cert_type,
								    int auth_length,unsigned char *auth
						);


/*
 * 	�����������Ա��ɫ
 * 	�����������Ա��ɫ��֤�������ߣ�֤�������߳�Ϊ��������Ա
 *	����������֤Ϊ������Ա
 */

int tcs_grant_admin_role(struct admin_cert_update *cert_update,
						int cert_type,
						int auth_length,unsigned char *auth);
/*
 *	ɾ����������Ա��
 * 	��֤�������ߴӶ�������Ա��ɾ��
 * 	����������֤Ϊ������Ա
 * 	ɾ��ʱ�ɲ���д֤������ݲ��֡�
 */

int tcs_remove_admin_role(struct admin_cert_update *cert_update,
		int cert_type,
		int auth_length,unsigned char *auth);


/*
 *	��ȡ����Ա֤���б�
 *	����ȫ������Ա֤�飬�����������֤�ù���Ա֤�飬�������������ݡ�
 */
int tcs_get_admin_list(struct admin_cert_item **list,
		int *num);

/*
 * ����TPCM������֤����
 */
int tcs_set_admin_auth_policies(struct admin_auth_policy_update *update,
				const char *uid, int cert_type, int auth_length,unsigned char *auth);
/*
 * ��ȡTPCM������֤����
 */
int tcs_get_admin_auth_policies(struct admin_auth_policy **list,
		int *num);

#endif /* TCSAPI_AUTH_H_ */
