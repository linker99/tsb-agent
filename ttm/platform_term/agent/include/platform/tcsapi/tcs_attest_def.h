
#ifndef TCSAPI_TCS_ATTEST_DEF_H_
#define TCSAPI_TCS_ATTEST_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#if defined platform_2700
#include <linux/time.h>
#endif
#else
#include <stdint.h>
#include <sys/time.h>
#endif
#include "tcs_constant.h"
#include "tcs_policy_def.h"


#define MAX_REMOTE_CERT_SIZE 	4096
#define MAX_POLICY_NAME_SIZE 	32

#define get_sub_version(x) (x >> 60)
#define get_major_version(x) (x & 0x0FFFFFFFFFFFFFFF)


enum {
	BOOT_PCR_BIOS = 1,	//����������ʼ�׶���BIOS�׶ε�PCR
	BOOT_PCR_BOOTLOADER,//����������ʼ�׶���BOOTLOADER�׶ε�PCR
	BOOT_PCR_KERNEL,	//����������ʼ�׶���KERNEL�׶ε�PCR
	BOOT_PCR_TSB,		//����������ʼ�׶���TSB�׶ε�PCR
};

enum{
	STATUS_TRUSTED,
	STATUS_UNTRUSTED,
	STATUS_UNKNOWN,
};

enum TPCM_FEATURES_BIT{
	TPCM_FEATURES_INTERCEPT_MEASURE = 0,
	TPCM_FEATURES_DYNAMIC_MEASURE,
	TPCM_FEATURES_SIMPLE_BOOT_MEASURE,
	TPCM_FEATURES_IMPORT_BIOS_MEASURE_RESULT,
	TPCM_FEATURES_FIRMWARE_UPGRADE,
	TPCM_FEATURES_FLASH_ACCESS,
	TPCM_FEATURES_SIMPLE_INTERCEPT_MEASURE,
};

/** TPCM LOG Type */
enum{
	LT_BOOT_MEASURE = 1,
	LT_DYNAMIC_MEASURE
};

enum POLICY_TYPE_ENUM{
	POLICY_TYPE_ADMIN_AUTH_POLICY = 0,		//������֤����
	POLICY_TYPE_GLOBAL_CONTROL_POLICY,		//ȫ�ֲ���
	POLICY_TYPE_BMEASURE_REF,				//����������׼ֵ
	POLICY_TYPE_DMEASURE,					//��̬��������
	POLICY_TYPE_PROCESS_DMEASURE, 			//���̶�̬����
	POLICY_TYPE_FILE_INTEGRITY, 			//������
	POLICY_TYPE_PROCESS_IDENTITY, 			//��������
	POLICY_TYPE_PROCESS_ROLE, 				//���̽�ɫ
	POLICY_TYPE_PTRACE_PROTECT, 			//���̸���
	POLICY_TYPE_TNC, 						//��������
	POLICY_TYPE_KEYTREE, 					//��Կ��
	POLICY_TYPE_STORE,						//�洢����
	POLICY_TYPE_LOG, 						//��Ʋ���
	POLICY_TYPE_NOTICE, 					//֪ͨ����
	POLICY_TYPE_CRITICAL_FILE_INTEGRITY,	//�ؼ��ļ�
	POLICY_TYPE_FILE_PROTECT,				//�ļ����ʿ��Ʋ���
	POLICY_TYPE_DEV_PROTECT,				//����-U������
	POLICY_TYPE_UDISK_PROTECT,				//����-��������
	POLICY_TYPE_NETWORK_CONTROL,			//�������
	POLICIES_TYPE_MAX,
};

#pragma pack(push, 1)
struct trust_evidence{
	uint64_t be_nonce;//���طű��
	uint32_t be_eval;//��������
	uint32_t be_boot_times;//������������	4�ֽ�	TPCM��������
	uint32_t be_tpcm_time;//�ڲ�ʱ�Ӽ���	4�ֽ�	TPCM�ڲ�ʱ�Ӽ���
	uint64_t be_tpcm_report_time;//TPCM�ϱ�ʱ��	8�ֽ�	TPCM�ϱ����ű����ʱ��
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
	unsigned char attached_hash[DEFAULT_HASH_SIZE];//�������ݵ�HASH
	unsigned char signature[DEFAULT_SIGNATURE_SIZE];
};
/*
 * �����ݺ�Ӧ��Զ�̿���֤��
 * Զ��֤����֤Э��
 */
struct trust_report_content{
	//uint32_t be_length;
	//uint32_t be_signature_length;
	uint64_t be_host_report_time;//����ʱ��	8�ֽ�	TPCM�����豸���뱨��ʱ��
	uint64_t be_host_startup_time;//ϵͳ����ʱ��	8�ֽ�	TPCM�����豸����ʱ��

	unsigned char host_id[MAX_HOST_ID_SIZE];//����ID	 32�ֽ�	TPCM�����豸ID
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];

	struct global_control_policy global_control_policy;//8 byte ����

	uint32_t be_eval;//��������	4�ֽ�	����100�֣���������ʧ��Ϊ0��
	uint32_t be_host_ip;//IP��ַ	4�ֽ�	TPCM�����豸IP��ַ

	uint32_t be_ilegal_program_load;//�Ƿ�����ִ�д���	4�ֽ�	TPCM��¼�ķǷ�����ִ�д���
	uint32_t be_ilegal_lib_load;//�Ƿ���̬����ش���	4�ֽ�	TPCM��¼�ķǷ���̬����ش���

	uint32_t be_ilegal_kernel_module_load;//�Ƿ��ں�ģ����ش���	4�ֽ�	TPCM��¼�ķǷ��ں�ģ����ش���
	uint32_t be_ilegal_file_access;//�Ƿ��ļ����ʴ���	4�ֽ�	TPCM��¼�ķǷ��ļ����ʴ���

	uint32_t be_ilegal_device_access;//�Ƿ��豸���ʴ���	4�ֽ�	TPCM��¼�ķǷ��豸���ʴ���
	uint32_t be_ilegal_network_inreq;//�Ƿ�������ʴ���	4�ֽ�	TPCM��¼�ķǷ�������ʴ���

	uint32_t be_ilegal_network_outreq;//�Ƿ���������������	4�ֽ�	TPCM��¼�ķǷ������������
	uint32_t be_process_code_measure_fail;//	�������ζ���ʧ�ܴ���	4�ֽ�	TPCM��¼�ĳ������ζ���ʧ�ܴ���

	uint32_t be_kernel_code_measure_fail;//�ں˴���ζ���ʧ�ܴ���	4�ֽ�	TPCM��¼���ں˴���ζ���ʧ�ܴ���
	uint32_t be_kernel_data_measure_fail;//�ں˹ؼ����ݶ���ʧ�ܴ���	4�ֽ�	TPCM��¼���ں˹ؼ����ݶ���ʧ�ܴ���

	uint32_t be_notify_fail;//����֪ͨ����	4�ֽ�	TPCM��¼�ķ���֪ͨʧ�ܵĴ���
	uint32_t be_boot_measure_result;//���������Ƿ�Ϸ�	4�ֽ�	0=�����Ϸ�
	//1=�������Ϸ�
	//2=״̬δ֪
	uint32_t be_boot_times;//������������	4�ֽ�	TPCM��������
	uint32_t be_tpcm_time;//�ڲ�ʱ�Ӽ���	4�ֽ�	TPCM�ڲ�ʱ�Ӽ���

	uint64_t be_tpcm_report_time;//TPCM�ϱ�ʱ��	8�ֽ�	TPCM�ϱ����ű����ʱ��

	uint32_t be_log_number;//��־����	4�ֽ�	TPCM���ͳɹ���־����
	unsigned char log_hash[DEFAULT_HASH_SIZE];	//	��־������hashֵ	32�ֽ�	������־��PSR��չֵ������������У��
	//		����������hashֵ	32�ֽ�	��ǰ���Ե�hashֵ������������У��
	unsigned char bios_pcr[DEFAULT_PCR_SIZE];
	unsigned char boot_loader_pcr[DEFAULT_PCR_SIZE];
	unsigned char kernel_pcr[DEFAULT_PCR_SIZE];
	unsigned char tsb_pcr[DEFAULT_PCR_SIZE];
	unsigned char boot_pcr[DEFAULT_PCR_SIZE];

};
struct trust_report{
	struct trust_report_content content;
	uint64_t be_nonce;//���طű��
	unsigned char signature[DEFAULT_SIGNATURE_SIZE];
};

struct remote_cert{
	uint32_t  be_alg;
	uint32_t  be_length;
	unsigned char id[MAX_TPCM_ID_SIZE];
	unsigned char cert[MAX_REMOTE_CERT_SIZE];
};

struct tpcm_info{//����֮ǰ�ĸ�ʽ
//���������õĿռ�
	uint64_t be_host_time;//��ȡ״̬��Ϣ��ʱ��	8�ֽ�
	struct global_control_policy global_control_policy;
	uint32_t be_cmd_handled;//�Ѵ�����������	4�ֽ�
	uint32_t be_cmd_pending;//��������������	4�ֽ�
	uint32_t be_cmd_error_param;//�����������������ֲ�������	4�ֽ�
	uint32_t be_cmd_error_refused;//�ܾ�����������������������	4�ֽ�
	uint32_t be_file_integrity_valid;//�����Ի�׼����Ч����	4�ֽ�
	uint32_t be_file_integrity_total;//�����Ի�׼��������	4�ֽ�
	uint32_t be_boot_measure_ref_number;//������׼������	4�ֽ�
	uint32_t be_dynamic_measure_ref_number;//��̬������׼������ 4�ֽ�
	uint32_t be_admin_cert_number;//����Ա֤������  4�ֽ�
	uint32_t be_trusted_cert_number;//���ε�֤������    4�ֽ�
	uint32_t be_boot_times;//��������	4�ֽ�
	uint64_t be_dmeasure_times;//��̬��������	8�ֽ�
	uint32_t be_file_integrity_measure_times;//����������������	4�ֽ�
	uint32_t be_file_notify_times;//֪ͨ����	4�ֽ�
	uint32_t be_tpcm_type;//TPCM����	4�ֽ�	TPCM�������ĸ�CPU
	uint32_t be_tpcm_total_mem;//���ڴ�	4�ֽ�
	uint32_t be_tpcm_available_mem;//�����ڴ�	4�ֽ�
	uint32_t be_tpcm_nvsapce_size;//�洢�ռ�(FLASH ����)	4�ֽ�
	uint32_t be_tpcm_nvsapce_availble_size;//���ô洢�ռ䣨FLASH����ʣ�ಿ�֣�	4�ֽ�
	//��������	4�ֽ�	��ǰΪ1
	uint32_t be_boot_trust_state;//��������״̬	4�ֽ�	0������
	//1�������ţ���δƥ���ֶΣ�
	//2��״̬δ֪����׼ֵδ����ʱ��������׼ֵΪȫ�㣩
	uint32_t be_trust_os_version;//���Ų���ϵͳ�汾��	4�ֽ�
	uint32_t be_cpu_firmware_version;//CPU�����̼��汾��
	uint32_t be_bios_firmware_version;//BIOS�̼��汾��
	uint32_t be_tpcm_firmware_version;//TPCM�汾��	4�ֽ�
	//��Ч�����׼������	4�ֽ�
	uint32_t be_tpcm_cpu_number;//CPU����	4�ֽ�
	uint32_t be_ek_generated;//EK�Ƿ�����	4�ֽ�
	uint32_t be_srk_generated;//���洢��Կ�Ƿ�����	4�ֽ�
	uint32_t be_pik_generated;//��PIK�Ƿ�����	4�ֽ�
	uint32_t be_pesistent_key_number;//�־ô洢��Կ����	4�ֽ�
	uint32_t be_alg_mode;//�㷨ʵ�֣�����Ӳ��	4�ֽ�	���㷨=1
	//Ӳ�㷨=2
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
};

struct policy_version{
	uint32_t be_policy;
	uint64_t be_version;
};

/** Boot measure log structure for every measure unit */

/** Boot measure log structure */
typedef struct{
	uint32_t uiType;
	uint32_t uiLength;
	uint32_t uiRelativeSec;
	uint32_t uiRelativeMsec;
	uint32_t uiStage;
	uint32_t uiResult;
	uint8_t  aucDigest[32];
	uint32_t uiNameLength;
	uint8_t  aucName[0];
}bmlog_st;


/** Dynamic measure log structure */
typedef struct{
	uint32_t uiType;
	uint32_t uiLength;
	uint32_t uiRelativeSec;
	uint32_t uiRelativeMsec;
	uint8_t  aucName[32];
    uint32_t uiResult;
    uint8_t  aucDigest[32];
}dmlog_st;


#pragma pack(pop)

struct tpcm_log{
	int type;
	int length;
	struct timeval time;
	char *log;
};


#endif /* TCSAPI_TCS_ATTEST_DEF_H_ */
