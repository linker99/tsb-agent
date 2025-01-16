
#ifndef TCSAPI_TCS_STORE_H_
#define TCSAPI_TCS_STORE_H_
#include "tcs_auth.h"
#include "tcs_store_def.h"

/*
 * 	�������ʧ�洢�ռ�
 */
int tcs_nv_define_space(
		uint32_t index, int size,
		unsigned char *ownerpasswd,unsigned char *usepasswd);

/*
// * 	���ݲ��Զ������ʧ�洢�ռ�
 */
int tcs_nv_define_space_on_policy(
		uint32_t index, int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy);
/*
 *	���������ֵķ���ʧ�洢�ռ�
 *	�Ὠ��������������ӳ���ϵ
 */
int tcs_nv_define_named_space(
		const char *name, int size,
		unsigned char *ownerpasswd,
		unsigned char *usepasswd);

/*
 *	���ݲ��Զ��������ֵķ���ʧ�洢�ռ�
 *	�Ὠ��������������ӳ���ϵ
 */
int tcs_nv_define_named_space_on_policy(
		const char *name,	int size,
		unsigned char *ownerpasswd,
		struct auth_policy *policy);

/*
 * 	ɾ������ʧ�洢�ռ�
 */
int tcs_nv_delete_space(uint32_t index,unsigned char *ownerpasswd);

/*
 * 	ͨ������ɾ������ʧ�洢�ռ�
 */
int tcs_nv_delete_named_space(const char *name,unsigned char *ownerpasswd);

/*
 * д�����ʧ����
 */
int tcs_nv_write(
		uint32_t index, int length,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	ͨ������д�����ʧ����
 */
int tcs_nv_named_write(
		const char *name, int length,
		unsigned char *data, unsigned char *usepasswd);
/*
 * 	��ȡ����ʧ����
 */
int tcs_nv_read(
		uint32_t index, int *length_inout,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	ͨ�����ֶ�ȡ����ʧ����
 */
int tcs_nv_named_read(
		const char *name, int *length_inout,
		unsigned char *data, unsigned char *usepasswd);

/*
 * 	��ȡ��������ʧ�洢�ռ��б�
 */
int tcs_read_nv_list(struct nv_info **array,int *number);

/*
 * 	�ͷ�NV��Ϣ�ڴ�
 */
void tcs_free_nv_list(struct nv_info *array,int number);

/*
 * 	����nv��Ϣ�б�
 */
int tcs_set_nv_list(struct nv_info *array, int number);

int tcs_is_nv_index_defined(uint32_t index);

int tcs_is_nv_name_defined(const char *name);

/*
 * ������ʧ����
 */
int tcs_save_mem_data(
		uint32_t index, int length,
		unsigned char *data, char *usepasswd);

/*
 * ��ȡ��ʧ����
 */
int tcs_read_mem_data(
		uint32_t index, int *length_inout,
		unsigned char *data, char *usepasswd);

#endif /* TCSAPI_TCS_STORE_H_ */
