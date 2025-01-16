#ifndef TCFAPI_TCF_FILE_INTEGRITY_H_
#define TCFAPI_TCF_FILE_INTEGRITY_H_
#include <stdint.h>
#include "../tcsapi/tcs_constant.h"

struct file_integrity_update;

struct file_integrity_item_user{
	unsigned int hash_length;
	unsigned int path_length;
	int is_control;//�Ƿ���п���
	int is_enable;//�Ƿ�����
	int is_full_path;//bool
	unsigned int extend_size;
	char *hash;
	char *path;
	char *extend_buffer;
	//const unsigned char *lib_hashs;
};

struct file_integrity_sync {
	uint64_t smajor;	/** ���汾�� */
	uint32_t sminor;	/** �ΰ汾�� */
	uint32_t length;	/** ���������� */
	uint32_t action;	/** ACTION */
	uint8_t *data;		/** ������ */
};

struct sync_version{
	uint64_t smajor;	/** ��ʼ���汾�� */
	uint32_t sminor;	/** ��ʼ�ΰ汾�� */
	uint64_t emajor;	/** ��ֹ���汾�� */
	uint32_t eminor;	/** ��ֹ�ΰ汾�� */
};

// white list (program reference) interface
/*
 * 	��ȡ��׼��
 */
int tcf_get_file_integrity(struct file_integrity_item_user **references,
		unsigned int from,unsigned int *inout_num);//proc ����

/*
 * 	׼�����»�׼�⡣
 */
int tcf_prepare_update_file_integrity(
		struct file_integrity_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct file_integrity_update **buffer,unsigned int *prepare_size);

/*
 * 	�����ļ������Ի�׼��
 * 	���á����ӡ�ɾ����
 */

int tcf_update_file_integrity(
		struct file_integrity_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth,
		unsigned char *local_ref, unsigned int local_ref_length);

/*
 *	�ͷŻ�׼���ڴ�
 */
void tcf_free_file_integrity(struct file_integrity_item_user * pp,unsigned int num);
///*
// * 	ͨ��HASH���ҳ����׼��
// */
//int tcf_get_file_integrity_by_hash(
//		struct file_integrity_item_user ** pp,int *num,
//		const unsigned char *hash, int hash_length);

///*
// * 	ͨ�����ֲ��ҳ����׼��
// */
//int tcf_get_file_integrity_by_name(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *name, int path_length);

///*
// * 	ͨ��·�����һ�׼��
// */
//int tcf_get_file_integrity_by_path(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *path, int path_length);


///*
// * 	��׼�ⰴ������ƥ��
// */
//int tcf_match_file_integrity_by_name(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length);
///*
// * 	��׼�ⰴ���ֺ�·��ƥ��
// */
//int tcf_match_file_integrity_by_name_and_path(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length,
//		const unsigned char *path, int path_length);
/*
 *	��ȡ��׼����Ч����
 */

int tcf_get_file_integrity_valid_number ( int *num);//proc ����
/*
 * 	��ȡ��׼��洢����
 */
int tcf_get_file_integrity_total_number (int *num);//proc ����

/*
 *	��ȡ��׼��������޸�����
 */
int tcf_get_file_integrity_modify_number_limit (int *num);//proc ����


/*
 * ��ȡ�ļ�������ͬ������
 */
int tcf_get_synchronized_file_integrity (struct sync_version *version, struct file_integrity_sync **file_integrity, int *num);

/*
 * �ͷ��ļ�������ͬ������
 */
int tcf_free_synchronized_file_integrity (struct file_integrity_sync **file_integrity, int num);

/*
 * 	׼�����¹ؼ��ļ������Ի�׼�⡣
 */
int tcf_prepare_update_critical_file_integrity(
		struct file_integrity_item_user *items, unsigned int num,
		unsigned char *tpcm_id, unsigned int tpcm_id_length,
		int action, uint64_t replay_counter,
		struct file_integrity_update **buffer, unsigned int *prepare_size);

/*
 * 	������¹ؼ��ļ������Ի�׼��
 */
int tcf_update_critical_file_integrity(
		struct file_integrity_update *references,
		const char *uid, int cert_type,
		unsigned int auth_length, unsigned char *auth);

/** ��ȡ�ؼ����»�׼�� */
int tcf_get_critical_file_integrity (
		struct file_integrity_item_user **references, unsigned int *num);

/** �ͷŹؼ����»�׼���ڴ� */
void tcf_free_critical_file_integrity (
		struct file_integrity_item_user *references, unsigned int num);


/*
 *	��ȡ�ļ������Կ�hash
 */
int tcf_get_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len);

/** ��ȡ�ؼ��ļ������Ի�׼��ժҪֵ */
int tcf_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len);

#endif /* TCFAPI_TCF_FILE_INTEGRITY_H_ */
