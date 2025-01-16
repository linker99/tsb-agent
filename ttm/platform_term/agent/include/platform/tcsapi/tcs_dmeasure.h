

#ifndef TCSAPI_TCS_DMEASURE_H_
#define TCSAPI_TCS_DMEASURE_H_
#include "tcs_dmeasure_def.h"

#pragma pack(push, 1)

struct dmeasure_process_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//process_dmesaure_item array,every item 4 byte align
};

struct dmeasure_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//dmeasure_item array,every item 4 byte align
};


struct dmeasure_reference_item{
	uint32_t be_hash_length;//
	uint32_t be_hash_number;//support multi version(���ڴ���οɱ�)
	uint32_t be_name_length;
	unsigned char data[0];//hash+name
};


struct dmeasure_reference_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];//dmeasure_item array,every item 4 byte align
};

#pragma pack(pop)

//��̬�������Թ���
/*
 * 	���¶�̬��������
 * 	���á����ӡ�ɾ����
 */

int tcs_update_dmeasure_policy(struct dmeasure_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);

//��̬�������Թ���
/*
 * 	���½��̶�̬��������
 * 	���á����ӡ�ɾ����
 */

int tcs_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	��ȡ��̬��������
 */
int tcs_get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length);//proc ����


/*
 * 	��ȡ���̶�̬��������
 */
int tcs_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length);//proc ����


/*
 * 	���ö�̬������׼ֵ
 */
int tcs_update_dmeasure_reference(struct dmeasure_reference_update *reference);

/*
* 	���ö�̬������׼ֵ������֤
 */
int tcs_update_dmeasure_reference_auth(struct dmeasure_reference_update *reference,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	��ȡ��̬������׼��
 */
int tcs_get_dmeasure_reference(struct dmeasure_reference_item **references,int *item_count,int *length);//proc ����



#endif /* TCSAPI_TCS_DMEASURE_H_ */
