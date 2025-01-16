#ifndef TRUNK_INCLUDE_TCFAPI_TCF_DEV_PROTECT_H_
#define TRUNK_INCLUDE_TCFAPI_TCF_DEV_PROTECT_H_

#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_dev_protect_def.h"
//ֱ�ӵ���tsb����
#include "../tsbapi/tsb_udisk.h"
/*
 * 	��ȡ������������
 */
int tcf_get_cdrom_protect_policy(struct cdrom_protect_item **references, unsigned int *inout_num);//proc ����


/*
 * 	���¹�����������
 * 	֧�����á�
 */

// int tcf_update_file_protect_policy(
// 		struct file_protect_update *references,
// 		const char *uid,int cert_type,
// 		unsigned int auth_length,unsigned char *auth);

int tcf_update_cdrom_protect_policy(
		struct cdrom_protect_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth);
/**/
int tcf_prepare_update_cdrom_protect_policy(
		struct cdrom_protect_item *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct cdrom_protect_update **buffer,unsigned int *prepare_size);
/*释放*/

void tcf_free_dev_protect_policy(struct cdrom_protect_item * pp);		
#endif /* TRUNK_INCLUDE_TCFAPI_TCF_DEV_PROTECT_H_ */
