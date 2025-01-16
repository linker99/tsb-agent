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

//����Ա֤��
/*
 * 	���ø�����Ա֤��
 * 	��֤������������Ϊ������Ա
 * 	�״�����������֤���ٴ���������֤
 * 	ʹ��֮ǰ�ĸ�����Ա֤�������֤��
 */
int tcf_set_admin_cert(struct admin_cert_update *update,
									int cert_type,
								    int auth_length,unsigned char *auth
						);


/*
 * 	�����������Ա��ɫ
 * 	�����������Ա��ɫ��֤�������ߣ�֤�������߳�Ϊ��������Ա
 *	����������֤Ϊ������Ա
 */

int tcf_grant_admin_role(struct admin_cert_update *cert_update,
						int auth_type,
						int auth_length,unsigned char *auth);
/*
 *	ɾ����������Ա��
 * 	��֤�������ߴӶ�������Ա��ɾ��
 * 	����������֤Ϊ������Ա
 * 	ɾ��ʱ�ɲ���д֤������ݲ��֡�
 */

int tcf_remove_admin_role(struct admin_cert_update *cert_update,
		int auth_type,
		int auth_length,unsigned char *auth);

/*
 *	��ȡ����Ա֤���б�
 *	����ȫ������Ա֤�飬�����������֤�ù���Ա֤�飬�������������ݡ�
 */
int tcf_get_admin_list(struct admin_cert_info **list,
		int *list_size);

/*
 * 	�ͷŹ���Ա֤���б��ڴ�
 *	�ͷ��ɶ�ȡ����Ա֤���б����ص��ڴ档
 */
int tcf_free_admin_list(struct admin_cert_info *list,
		int list_size);

/*
 * ����TPCM������֤����
 */
int tcf_set_admin_auth_policies(struct admin_auth_policy_update *update,
			const char *uid, int auth_type,
				int auth_length,unsigned char *auth);
/*
 * ��ȡTPCM������֤����
 */
int tcf_get_admin_auth_policies(struct admin_auth_policy **list,
		int *list_size);

#endif /* TCFAPI_TCF_AUTH_H_ */
