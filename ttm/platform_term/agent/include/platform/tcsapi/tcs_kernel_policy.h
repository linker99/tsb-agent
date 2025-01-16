
#ifndef TCSAPI_TCS_KERNEL_POLICY_H_
#define TCSAPI_TCS_KERNEL_POLICY_H_

#include "tcs_process_def.h"
#include "tcs_policy_def.h"
#include "tcs_dmeasure_def.h"
#include "tcs_protect_def.h"
#include "tcs_tnc_def.h"

/*
 * ��ȡȫ����������
 */
int tcsk_get_process_ids(struct process_identity **ids,int *num,int *length);

/*
 * ��ȡȫ�����̽�ɫ
 */
int tcsk_get_process_roles(struct process_role **roles,int *num,int *length);

/*
 * ��ȡȫ�ֿ��Ʋ���
 */
int tcsk_get_global_control_policy(struct global_control_policy *policy);//proc ����

/*
 * 	��ȡ��̬��������
 */
int tcsk_get_dmeasure_policy(struct dmeasure_policy_item **policy,int *item_count,int *length);//proc ����

/*
 * 	��ȡ���̶�̬��������
 */
int tcsk_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length);//proc ����

/*
 * ��ȡ���̸��ٱ�������
 */	
int tcsk_get_ptrace_protect_policy(struct ptrace_protect **policy, int *length);//proc ����

/*
 * ��ȡ�������Ӳ���
 */
int tcsk_get_tnc_policy(struct tnc_policy **policy, int *length);//proc ����

#endif /* TCSAPI_TCS_KERNEL_POLICY_H_ */
