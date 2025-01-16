
#ifndef TCSAPI_TCS_POLICY_DEF_H_
#define TCSAPI_TCS_POLICY_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"

enum{
	PROCESS_MEASURE_MODE_SOFT,//TSB����
	PROCESS_MEASURE_MODE_TCS_CHECK,//TSB���㣬TCSƥ��
	PROCESS_MEASURE_MODE_TCS_MEASURE,//TCS����
	PROCESS_MEASURE_MODE_AUTO,//�Զ�ѡ�������ʽ
};
enum{
	PROCESS_MEASURE_MATCH_HASH_ONLY,//ֻƥ��HASH
	PROCESS_MEASURE_MATCH_WITH_PATH,//ƥ��HASH��·��
};

enum{
	PROCESS_DMEASURE_REF_START,//ƥ�������ɼ�ֵ
	PROCESS_DMEASURE_REF_LIB,//ƥ�������Ի�׼��
	//PROCESS_DMEASURE_REF_SEPCIFIC_LIB//ƥ��һ���ض���
};
enum{
	PROCESS_DMEASURE_MATCH_HASH_ONLY,//ֻƥ��HASH
	PROCESS_DMEASURE_MATCH_WITH_PATH,//ƥ��HASH��·��
};
enum{
	PROCESS_VERIFY_MODE_DEFAULT ,//������ָ����ʽ��
	PROCESS_VERIFY_MODE_NO_LIB ,//����֤�⡣
	PROCESS_VERIFY_MODE_REF_LIB ,//��ȫ�ֻ�׼����֤��
	PROCESS_VERIFY_MODE_SPECIFIC_LIB,//��ר�Ż�׼����֤��
};
enum{
	PROCESS_DMEASURE_OBJECT_ID_FULL_PATH,//ȫ·��
	PROCESS_DMEASURE_OBJECT_ID_PROCESS,//������
	PROCESS_DMEASURE_OBJECT_ID_HASH,//HASH
};
enum{
	PROCESS_DMEASURE_MODE_MEASURE = 1,//����
	PROCESS_DMEASURE_MODE_NON_MEASURE,//������
};
enum{
	POLICY_SWITCH_OFF,
	POLICY_SWITCH_ON,
};

#pragma pack(push, 1)

#define DMEASURE_CONFIG_DELAY 60

struct global_control_policy{

	uint32_t be_size;
	uint32_t be_boot_measure_on;//on or not,Ĭ��ֵΪ�����ر�ʱ������BIOS,ֱ�ӷ��سɹ��� #Ĭ��ֵ: 1
	uint32_t be_program_measure_on;//on or not��Ĭ��ֵΪ�������ذ���������ʵ�ʿ��ơ�							#Ĭ��ֵ: 1
    uint32_t be_dynamic_measure_on;//on or not 											#Ĭ��ֵ: 1

	uint32_t be_boot_control;//control or not 											#Ĭ��ֵ: 0
	uint32_t be_program_control;//control or not										#Ĭ��ֵ: 1

	//uint32_t be_policy_require_auth;
	//uint32_t be_static_reference_auth;
	//uint32_t be_dynamic_reference_auth;
//	uint32_t be_policy_auth;//none��hmac��signature
//	uint32_t be_static_reference_auth;//none��hmac��signature
//	uint32_t be_dynamic_reference_auth;//none
//	uint32_t be_auth_reference_auth;//hmac��signature

	//uint32_t be_policy_replay_check;//check or not?										#Ĭ��ֵ: 1
	//uint32_t be_static_reference_replay_check;//check or not?							#Ĭ��ֵ: 1
	//uint32_t be_dynamic_reference_replay_check;//check or not?							#Ĭ��ֵ: 1

	uint32_t be_tsb_flag1;//TSB ר�ñ�ǣ�λ0���Ա���ģ���ж�أ�λ1���Ա������̷�ɱ�� Ĭ��ֵ0
	uint32_t be_tsb_flag2;//TSB ר�ñ�Ǳ���
	uint32_t be_tsb_flag3;//TSB ר�ñ�Ǳ���

	
	//uint32_t be_policy_require_process_bind;//if bind process
	//uint32_t be_static_reference_require_process_bind;//if bind process
	//uint32_t be_dynamic_reference_require_process_bind;//if bind process
	//uint32_t be_policy_require_state_bind;//if state process
	//uint32_t be_static_reference_require_state_bind;//if state process
	//uint32_t be_dynamic_reference_require_state_bind;//if state process
	//uint32_t be_process_bind_mode;//program_name,main_code,libs

	uint32_t be_program_measure_mode;//software_measure,tcs_check,tcs_measure,auto		#Ĭ��ֵ: PROCESS_MEASURE_MODE_TCS_MEASURE
	uint32_t be_measure_use_cache;//disabe enable										#Ĭ��ֵ: 1

	uint32_t be_dmeasure_max_busy_delay;//��̬��������ӳ٣������ƣ�									#Ĭ��ֵ: 300
	uint32_t be_process_dmeasure_ref_mode;//����ʱ�ɼ����ļ������Կ⣿								#Ĭ��ֵ: PROCESS_DMEASURE_REF_START
	uint32_t be_process_dmeasure_match_mode;//ֻƥ��HASH������Ҳ·��								#Ĭ��ֵ: PROCESS_DMEASURE_MATCH_HASH_ONLY
	uint32_t be_program_measure_match_mode;//ֻƥ��HASH������Ҳ·��								#Ĭ��ֵ: PROCESS_MEASURE_MATCH_HASH_ONLY
	uint32_t be_process_dmeasure_lib_mode;//�Ƿ������										#Ĭ��ֵ: PROCESS_DMEASURE_MODE_NON_MEASURE
	uint32_t be_process_verify_lib_mode;//�Ƿ�����⣿�ļ������Կ⣿ʹ��������֤�⡣	       					#Ĭ��ֵ: PROCESS_VERIFY_MODE_DEFAULT
	uint32_t be_process_dmeasure_sub_process_mode;//�ӽ��̶���ģʽ								#Ĭ��ֵ: PROCESS_DMEASURE_MODE_MEASURE
	uint32_t be_process_dmeasure_old_process_mode;//������Чǰ���������̶���ģʽ						#Ĭ��ֵ: PROCESS_DMEASURE_MODE_MEASURE
	uint32_t be_process_dmeasure_interval;//�����������										#Ĭ��ֵ:	 60000
	//uint32_t be_padding;//
};


struct global_control_policy_update{
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct global_control_policy policy;
};


struct policy_report_content{
	struct global_control_policy global_control_policy;
	//uint64_t be_nonce;//
	uint32_t be_file_integrity_valid;
	uint32_t be_file_integrity_total;
	uint32_t be_boot_measure_ref_bumber;
	uint32_t be_dynamic_measure_ref_bumber;
	uint32_t be_admin_cert_number;
	//uint32_t be_trusted_cert_number;
	unsigned char program_reference_hash[DEFAULT_HASH_SIZE];
	unsigned char boot_reference_hash[DEFAULT_HASH_SIZE];
	unsigned char dynamic_reference_hash[DEFAULT_HASH_SIZE];
	unsigned char admin_cert_hash[DEFAULT_HASH_SIZE];//��֤��+����֤��
	//unsigned char trusted_cert_hash[32];
};
struct policy_report{
	uint64_t be_nonce;
	struct policy_report_content content;
	unsigned char signiture[64];
};
#pragma pack(pop)

#endif /* TCSAPI_TCS_POLICY_DEF_H_ */
