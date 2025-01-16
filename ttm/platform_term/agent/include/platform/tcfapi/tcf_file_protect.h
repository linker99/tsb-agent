#ifndef TCF_FILE_PROTECT_H_
#define TCF_FILE_PROTECT_H_
#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_file_protect_def.h"
struct file_protect_update;

struct file_protect_privileged_process_user{
	uint32_t privi_type;//ALL ,READ_ONLY
	unsigned char *path;// 0 terninated
	unsigned char *hash;
};

struct file_protect_item_user{
	//unsigned int total_length;//sizeof(structfile_protect_item) + path_length + privileged_process_length
	unsigned int type;//write_protect,read_protect
	unsigned int measure_flags;
	unsigned char *path;
	int privileged_process_num;
	struct file_protect_privileged_process_user **privileged_processes;
};


/*
 * 	��ȡ�ļ���������
 */
int tcf_get_file_protect_policy(struct file_protect_item_user **references, unsigned int *inout_num);//proc ����

/*
 * 	׼�����²��Կ⡣
 */
int tcf_prepare_update_file_protect_policy(
		struct file_protect_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct file_protect_update **buffer,unsigned int *prepare_size);

/*
 * 	�����ļ���������
 * 	���á����ӡ�ɾ����
 */

int tcf_update_file_protect_policy(
		struct file_protect_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth);

/*
 *	�ͷ��ļ������ڴ�
 */
void tcf_free_file_protect_policy(struct file_protect_item_user * pp,unsigned int num);
#endif /* TCF_FILE_PROTECT_H_ */
