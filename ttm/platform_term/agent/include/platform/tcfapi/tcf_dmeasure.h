#ifndef TCFAPI_TCF_DMEASURE_H_
#define TCFAPI_TCF_DMEASURE_H_
#include <stdint.h>
#define MAX_DMEASURE_HASH_VERSION_NUMBER 8

struct dmeasure_policy_update;
struct dmeasure_reference_update;
struct dmeasure_process_policy_update;

struct dmeasure_policy_item_user{
	char *name;
	int type;
	int interval_milli;
};

struct dmeasure_process_item_user{
	uint8_t object_id_type;//�����ʶ����ȫ·������������HASH
	uint8_t sub_process_mode;//�ӽ��̣���������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint8_t old_process_mode;//������Чǰ�������Ľ��̣���������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint8_t share_lib_mode;//�����⣬��������������Ĭ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint32_t measure_interval;//����������룬0ΪĬ�ϣ���ȫ�ֲ��Կ��ƣ�
	uint16_t object_id_length; //���峤��
	char *object_id;//�����ʶ��ȫ·������������HASH��
};

//���̶�̬����
struct dmeasure_reference_item_user{
	int hash_length;//
	int hash_number;//support multi version(���ڴ���οɱ�)
	char  *hash_buffer;//length=hash_length  * hash_number
	char *name;//hash+name
};




/*
 * 	׼�����¶�̬��������
 */
int tcf_prepare_update_dmeasure_policy(
		struct dmeasure_policy_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_policy_update **policy,int *olen);

/*
 * 	׼�����½��̶�̬��������
 */
int tcf_prepare_update_dmeasure_process_policy(
		struct dmeasure_process_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_process_policy_update **policy,int *olen);

/*
 * 	���¶�̬��������
 * 	����
 */

int tcf_update_dmeasure_policy(struct dmeasure_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	���¶�̬��������
 * 	���á����ӡ�ɾ����
 */

int tcf_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	��ȡ��̬��������
 */
int tcf_get_dmeasure_process_policy(struct dmeasure_process_item_user **policy,int *item_count);//proc ����


/*
 * 	�ͷŽ��̶�̬���������ڴ�
 */
void tcf_free_dmeasure_process_policy(struct dmeasure_process_item_user *policy,int item_count);//proc ����

/*
 * 	��ȡ��̬��������
 */
int tcf_get_dmeasure_policy(struct dmeasure_policy_item_user **policy,int *item_count);//proc ����

/*
 * 	�ͷŶ�̬���������ڴ�
 */
void tcf_free_dmeasure_policy(struct dmeasure_policy_item_user *policy,int item_count);//proc ����

/*
 * 	׼����̬��������
 */
int tcf_prepare_update_dmeasure_reference(
		struct dmeasure_reference_item_user *items,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct dmeasure_reference_update **reference,int *olen);
/*
 * 	���ö�̬������׼ֵ
 */
int tcf_update_dmeasure_reference(struct dmeasure_reference_update *reference);

/*
* 	���ö�̬������׼ֵ������֤
 */
int tcf_update_dmeasure_reference_auth(struct dmeasure_reference_update *reference,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);


/*
 * 	��ȡ��̬������׼��
 */
int tcf_get_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count);//proc ����

/*
 * 	�ͷŶ�̬������׼ֵ�ڴ�
 */
void tcf_free_dmeasure_reference(struct dmeasure_reference_item_user **references,int *item_count);//proc ����

#endif /* TCFAPI_TCF_DMEASURE_H_ */
