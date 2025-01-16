
#ifndef TCFAPI_TCF_PROCESS_H_
#define TCFAPI_TCF_PROCESS_H_
#include <stdint.h>
#include "tcsapi/tcs_process_def.h"
struct process_identity_update;
struct process_role_update;

struct process_role_user{
	int member_number;
	unsigned char *name;
	unsigned char **members;
};

struct process_identity_user{
	unsigned char *name;
	uint32_t hash_length;
	int specific_libs;
	int lib_number;
	unsigned char *hash;
};

/*
 * ׼�����½�������
 */
int tcf_prepare_update_process_identity(
		struct process_identity_user *process_ids,int id_number,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct process_identity_update **update,int *olen
		);

/*
 * ���½������ݡ�
 * ���á����ӡ�ɾ�����޸ġ�
 */
int tcf_update_process_identity(
		struct process_identity_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);

/*
 * ��ȡȫ����������
 */
int tcf_get_process_ids(struct process_identity_user **ids,int *num);

/*
 * ��ȡָ����������
 */
int tcf_get_process_id(const unsigned char *name,struct process_identity_user **ids,int *num);

/*
 * �ͷŽ��������ڴ�
 */
void tcf_free_process_ids(struct process_identity_user *ids,int num);
/*
 * ׼�����½��̽�ɫ
 */
int tcf_prepare_update_process_roles(
		struct process_role_user *roles,int roles_number,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct process_role_update **update,int *olen
		);

/*
 * ���½��̽�ɫ�⡣
 * ���á����ӡ�ɾ�����޸ġ�
 */
int tcf_update_process_roles(struct process_role_update *update,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);

/*
 * ��ȡȫ�����̽�ɫ
 */
int tcf_get_process_roles(struct process_role_user **roles,int *num);


/*
 * ��ȡָ�����̽�ɫ
 * �������һ��
 */
int tcf_get_process_role(const unsigned char *name,struct process_role_user **roles);
/*
 * �ͷŽ��̽�ɫ�ڴ�
 */
void tcf_free_process_roles(struct process_role_user *roles,int num);

#endif /* TCFAPI_TCF_PROCESS_H_ */
