

#ifndef TCSAPI_TCS_KERNEL_H_
#define TCSAPI_TCS_KERNEL_H_
#ifdef __KERNEL__
#include <linux/types.h>
#if defined platform_2700
#include <linux/time.h>
#endif
#endif
#include "tcs_attest_def.h"
#include "tcs_kernel_def.h"

#define MAX_NOTIFY_SIZE  48
#define MAX_DMEASURE_NAME_SIZE	32
#define MAX_NOTIFY_CALL_BACK	10

/** Operation for collection_and_measure */
enum{
	OP_CTX_DM_INIT_COLLECT,	/** Dynamic measure init value collect */
};

enum FILE_INTEGRITY_TYPE{
	FILE_INTEGRITY_TYPE_PROCESS_EXEC = 1,
	FILE_INTEGRITY_TYPE_DYNAMIC_LIBRARY,
	FILE_INTEGRITY_TYPE_KERNEL_MODULE,
};

#pragma pack(push, 1)

struct collection_context{
	uint32_t type;
	uint32_t name_length;
	uint8_t  name[MAX_DMEASURE_NAME_SIZE];
	uint32_t data_length;
	uint64_t data_address;	/** Physical Address */
};

struct tsb_runtime_info{
	uint32_t illegalProcessExecCount;
	uint32_t illegalDynamicLibLoadCount;
	uint32_t illegalKernelModuleLoadCount;
	uint32_t illegalFileAccessCount;
	uint32_t illegalDeviceAccessCount;
	uint32_t illegalNetworkVisitCount;
	uint32_t illegalNetworkRequestCount;
	uint32_t measureProcessCodeFailureCount;
	uint32_t measureKdataMeasureFailCount;
	uint32_t measureKcodeMeasureFailCount;
};

#pragma pack(pop)

struct tpcm_notify{
	int type;
	int length;
	char notify[MAX_NOTIFY_SIZE];
};
#define MAX_PROCESS_IDENTITY_LENGTH 128
#define MAX_PROCESS_ROLE_LENGTH 128
struct process_identity_callback{
	int (* get_process_identity)
		(unsigned char *process_name,int *process_name_length);
	int (* is_role_member)
			(const unsigned char *role_name);
};
//struct notify_callback{
//	void (*log_func)(struct tpcm_log *log);
//	void (*notify_func)(struct tpcm_notify *notify);
//};


/*
 * �ļ���������������������
 */
int tcsk_integrity_measure(
		uint32_t path_len, void *path_addr, uint32_t type,
		uint32_t num_block,struct physical_memory_block *blocks,
		uint32_t *tpcmRes,
		uint32_t *mrLen,	unsigned char *mresult);
/*
 * �ļ�������顢���������
 */
int tcsk_integrity_measure_simple (
          int path_len, void *path_addr, uint32_t type,
          int hash_length, unsigned char *hash, uint32_t *tpcmRes);


/** Collect and measure context sturcture */

int tcsk_collection_and_measure(
   uint32_t operation, uint32_t ctxNum,
   struct collection_context *ctx,
   uint32_t *tpcmRes,
   uint32_t *mrLen, unsigned char *mResult);

int tcsk_get_tpcm_log(uint32_t *length, unsigned char *log, uint32_t *tpcmRes);


/*
 * ������ʧ����
 */
int tcsk_save_mem_data(
		uint32_t index, int length,
		unsigned char *data, char *usepasswd);

/*
 * ��ȡ��ʧ����
 */
int tcsk_read_mem_data(
		uint32_t index, int *length_inout,
		unsigned char *data, char *usepasswd);
/*
 * TSB ��TSSע��������֤�ص�����
 */
int tcsk_register_process_identity_callback(
		struct process_identity_callback *process_identity_callback);
/*
 * TSB ע��������֤�ص�����
 */
int tcsk_unregister_process_identity_callback(
		struct process_identity_callback *process_identity_callback);

/*
 * 	��ȡTPCM����
 */
int tcsk_get_tpcm_features(uint32_t *features);


/*
 *	 ��ȡ���ؿ���״̬
 */
int tcsk_get_trust_status(uint32_t *status);

/*
 *	 ͬ�����ؿ���״̬
 */
int tcsk_sync_trust_status (uint32_t type);


/*
 * 	��ȡLicense״̬
 */
int tcsk_get_license_status(int *status,int *left);//proc����

/** ��ȡLicense��Ϣ */
int tcsk_get_license_info (int *status, uint64_t *deadline);

typedef void (*log_call_back)(struct tpcm_log *log);
int tcsk_register_log_callback(log_call_back log_back_func_n );
int tcsk_unregister_log_callback(log_call_back log_back_func_n );


typedef void (*notify_call_back)(struct tpcm_notify *notify);
int tcsk_register_notify_callback(notify_call_back notify_back_func_n );
int tcsk_unregister_notify_callback(notify_call_back notify_back_func_n );

typedef void (*tsb_runtime_info_getter)(struct tsb_runtime_info *tsb_info);
int tcsk_register_tsb_runtime_info_getter(tsb_runtime_info_getter getter );
int tcsk_unregister_tsb_runtime_info_getter(tsb_runtime_info_getter getter );

typedef int (*tsb_measure_env)(void);
int tcsk_register_tsb_measure_env_callback (tsb_measure_env callback);
int tcsk_unregister_tsb_measure_env_callback (tsb_measure_env callback);

/*
 *	��ȡ�ļ������Կ�hash
 */
int tcsk_get_file_integrity_digest(unsigned char *digest ,unsigned int *digest_len);

/** ��ȡ�ؼ��ļ������Ի�׼��ժҪֵ */
int tcsk_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len);

#endif /* TCSAPI_TCS_KERNEL_H_ */
