
#ifndef INCLUDE_TCSAPI_TCS_TNC_DEF_H_
#define INCLUDE_TCSAPI_TCS_TNC_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#pragma pack(push, 1)

struct tnc_policy_item{
	uint32_t be_protocol;//Э�飺udp or tcp
	uint32_t be_remote_ip;//�Զ�IP,0��ʾ�κ�
	uint32_t be_local_ip;//����IP,0��ʾ�κ�
	uint16_t be_remote_port;//�Զ˶˿�,0��ʾ�κ�
	uint16_t be_local_port;//���ض˿�,0��ʾ�κ�

};
struct tnc_policy{
	uint32_t be_exception_number;//���������	
	uint16_t be_server_port;//�������Ķ˿�
	uint16_t be_control_mode;//����ģʽ��Ĭ��ȫ���ơ�Ĭ�ϲ�����
	uint8_t  encrypt_auth;//Ҫ���ļ�����֤
	uint8_t  server_testify;//Ҫ�󸽼ӹ�������֤ʵ���Զ˿���״̬��
	uint8_t  report_auth_fail;//��������Ļ㱨������֤ʧ��
	uint8_t  report_session;//��������Ļ㱨�Ự���������ڡ�ɾ��
	uint32_t be_session_expire;//�Ự����ʱ�䣨���ӣ���0������
	uint32_t be_server_ip;//��������IP��ַ
	struct tnc_policy_item exceptions[0];//��������
};

struct tnc_policy_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct tnc_policy policy[0]; // tnc_policy
};

#pragma pack(pop)

#endif /* INCLUDE_TCSAPI_TCS_TNC_DEF_H_ */
