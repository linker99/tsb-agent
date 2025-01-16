
#ifndef TCSAPI_TCS_LICENSE_H_
#define TCSAPI_TCS_LICENSE_H_
//#include "tcsapi/tcs_constant.h"
#include "tcs_license_def.h"
/*
 * 	����License����
 * 	�����������������License����License�����͸�TPCM���ɳ��̽�����Ȩ
 * 	����TPCM�Դ�����������Ȩ������Ҫ����������Ȩ��
 */
int tcs_generate_license_request(struct license_req *req,const struct license_param *param);

/*
 * 	����License
 * 	��TPCM����������Ȩ��License�����뵽TPCM֮�С�
 *	����TPCM�Դ�����������Ȩ������Ҫ����������Ȩ��
 */
int tcs_import_license(struct license *license);

//int tcs_upgrade_license(struct license *license);

/*
 * 	��ȡLicense״̬
 */
int tcs_get_license_status(int *status,int *left);//proc����


/*
 * 	��ȡLicense��Ϣ
 */
int tcs_get_license_info(int *status, uint64_t *deadline);

/*
 * 	����������
 * 	���¿�ʼ�����ڼ�ʱ��ͬʱ�����ȫ�����ݡ�
 */
int tcs_reset_test_license(void);

#endif /* TCSAPI_TCS_LICENSE_H_ */
