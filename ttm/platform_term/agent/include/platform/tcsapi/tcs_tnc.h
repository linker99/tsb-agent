
#ifndef INCLUDE_TCSAPI_TCS_TNC_H_
#define INCLUDE_TCSAPI_TCS_TNC_H_
#include "tcs_tnc_def.h"

/*
 * ���¿����������Ӳ��ԡ�
 * ֻ������
 */
int tcs_update_tnc_policy(struct tnc_policy_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * ��ȡ�����������Ӳ���
 */
int tcs_get_tnc_policy(struct tnc_policy **tnc_policy,int *length);

#endif /* INCLUDE_TCSAPI_TCS_TNC_H_ */
