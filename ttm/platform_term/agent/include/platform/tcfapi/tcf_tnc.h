
#ifndef INCLUDE_TCFAPI_TCF_TNC_H_
#define INCLUDE_TCFAPI_TCF_TNC_H_
#include "../tcsapi/tcs_tnc_def.h"
/*
 * ���¿����������Ӳ��ԡ�
 * ֻ������
 */
int tcf_update_tnc_policy(struct tnc_policy_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * ��ȡ�����������Ӳ���
 */
int tcf_get_tnc_policy(struct tnc_policy **tnc_policy,int *length);


#endif /* INCLUDE_TCFAPI_TCF_TNC_H_ */
