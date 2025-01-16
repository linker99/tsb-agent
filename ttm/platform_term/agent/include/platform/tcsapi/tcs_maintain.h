
#ifndef TCSAPI_TCS_MAINTAIN_H_
#define TCSAPI_TCS_MAINTAIN_H_
#define MAX_BACKUP_KEY_SIZE 32

#include <stdint.h>
#include "tcs_constant.h"

#pragma pack(push, 1)
struct backup_param{
	uint32_t be_size;
	uint32_t be_backup_key_len;
	const unsigned char backup_key[MAX_BACKUP_KEY_SIZE];//���ڼ��ܿ��ڲ����ݵĶԳƣ�ֻ�й���Ա֪����Կ��
};

struct shell_passwd{
		uint64_t be_replay_counter;
		unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
		uint32_t be_password_length;
		unsigned char password[0];
};
#pragma pack(pop)
//struct backup_data_encrpty_header{
//	uint32_t be_size;
//	uint32_t be_key_size;//��Կ���ܵĳ�����Կ
//	uint32_t be_data_size;//
//	unsigned char all[0];
//};

/*
 * 	��ʼ��TPCM
 * 	�����Ҫ�����ɱ�����Կ
 * 	��ȡ��������ģ�飨TCM����������Ȩ�ޡ�
 * 	�贫���������ģ�飨TCM������֤��Ϣ��
 *
 */
int tcs_init(unsigned char *passwd);

/*
 *	�޸�TCM��������֤��Ϣ
 */
int tcs_change_tcm_owner_auth(unsigned char *oldpass,unsigned char *newpass);

/*
 * 	��������
 * 	1 ���ɱ��ݵ����ݰ�����Ҫ��SRK��
 * 	2 ���ݵ����ݰ����ȼ���HASH,�����ù���Ա������Կ���ܣ��������ݰ� + HASH����
 * 	3 ���ɳ��̱�����Կ�����ж��μ���(��һ�ּ��ܵ�����  + License��Ϣ + HASH��
 * 	4 ͨ�����̹�Կ���ܼ��ܳ��̱�����Կ��
 *	backup_key//���ڼ��ܿ��ڲ����ݵĶԳƣ�ֻ�й���Ա֪����Կ��
 */
int tcs_backup(uint32_t backup_key_len,const unsigned char *backup_key,unsigned char *backup_data,int *olen_inout);

/*
 * 	TPCM���ݻָ�
 * 	�������Ѻ��¹ʻָ����漰����Ȩ�޻ָ����ɹ���Ա��TPCM����Эͬ���
 * 	�ָ�����
 * 	0)  �����µ�֤������,�뱸�ݵ�����һ���ύ����̩����̩���ɻָ���,�ָ�������TPCM�ı�����Կ����
 * 	1��  �ñ�����Կ���ܱ������ݣ���Ҫ��license�͵�һ�����ģ�
 * 	2��  ��֤����ǩ��
 * 	3��  �ñ�����Կ���ܵ�һ�����ݣ���Ҫ��SRK��������֤�����ԡ�
 * 	4��  �ָ��������ݰ���������license��
 * 	5)  �����µ�license
 */
int tcs_restore(uint32_t restore_data_len, unsigned char *restore_data, uint32_t backup_key_len,const unsigned char *backup_key);
//Instead, they can
//only be used to decrypt certificates of other TPM-generated keys, and this can only be done at the
//request of the owner of the TPM cooperating with a certificate authority (CA).

//int tcs_init();
/*
 * 	����TPCM�̼���
 * 	������TPCM�̼���ͬ�������ᱣ���û����ݺ�����Ȩ��
 * 	����֮ǰ����������ʽ
 */
int tcs_upgrade(unsigned char *upgrade_data,int length);

/*
 * 	����TPCM����̨���룬
 * 	�����ڲ�����������������£�
 * 	�޸Ŀ��Ʋ��ԣ��û��������������������н�һ��ά��������
 *	���ӿڸı�TPCM����̨���룬���TPCM�����ı���������
 */
int tcs_set_shell_password(struct shell_passwd *passwd,const char *uid,int auth_type,
		   int auth_length,unsigned char *auth);

/*
 * ִ����������
 * �ڹ��������޷����ӵ�������ɵ�����������ڱ���ִ�С�
 * ��������Ҳ��������������������
 * ��UEFI��GRUB����ͨ��������������ı���Ʋ��ԣ��Ա�ϵͳ�ܹ���������
 */
int tcs_exec_offline_cmd(const char *offcmd,int len, char *offres, int *olen);

/*
 * ��д����
 */

#endif /* TCSAPI_TCS_MAINTAIN_H_ */
