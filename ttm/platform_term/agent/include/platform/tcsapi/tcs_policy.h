
#ifndef TCSAPI_TCS_POLICY_H_
#define TCSAPI_TCS_POLICY_H_

#include "tcs_policy_def.h"
//enum{
//	PROCESS_BIND_MODE_NAME,
//	PROCESS_BIND_MODE_MAIN_CODE,//or grant
//	PROCESS_BIND_MODE_MAIN_AND_LIBS_CODE
//};

enum MEASURE_CTRL_TYPE{
	CTRL_TYPE_BOOT_MEASURE = 1,
	CTRL_TYPE_DYNAMIC_MEASURE,
};

#pragma pack(push, 1)
struct measure_ctrl_switch{
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	uint32_t be_type;
	uint32_t be_control;
};
#pragma pack(pop)


//int tcs_test_reset();

//ͨ�ÿ��Ʋ��Թ���
/*
 * ����ȫ�ֿ��Ʋ���
 * uidΪ��ʱ��ѯ���й�����֤��
 */
int tcs_set_global_control_policy(
		struct global_control_policy_update *data,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);//proc����������������֤

/*
 * ��ȡȫ�ֿ��Ʋ���
 */

int tcs_get_global_control_policy(struct global_control_policy *policy);//proc ����

/*
 * ��ȡ���Ա���
 * ������ǩ�ģ�
 */

int tcs_get_policy_report(struct policy_report *policy_report,uint64_t nonce);//proc ����


/*
 * ���������������ƿ���
 * ����ȫ�ֲ��Ա��be_boot_control | be_program_control
 */
int tcs_set_measure_control_switch (struct measure_ctrl_switch *ctrl,
					const char *uid,int auth_type, int auth_length,unsigned char *auth);

//int tcs_set_reference_admin_policy(struct auth_policy *policy);
//struct auth_policy{
//	unsigned int policy_flags;
//	unsigned char *process_or_role;
//	unsigned int *user_or_group;
//	unsigned char *password;
//};



#endif /* TCSAPI_TCS_POLICY_H_ */
