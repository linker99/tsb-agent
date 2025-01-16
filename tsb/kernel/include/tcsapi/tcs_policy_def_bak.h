

#ifndef TCSAPI_TCS_POLICY_DEF_H_
#define TCSAPI_TCS_POLICY_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
enum{
	PROCESS_DMEASURE_REF_START,//匹配启动采集值
	PROCESS_DMEASURE_REF_LIB,//匹配完整性基准库
	//PROCESS_DMEASURE_REF_SEPCIFIC_LIB//匹配一组特定库
};

enum{
	PROCESS_DMEASURE_MATCH_HASH_ONLY,//只匹配HASH
	PROCESS_DMEASURE_MATCH_WITH_PATH,//匹配HASH和路径
};

enum{
	PROCESS_DMEASURE_LIB_NOT = 1,//不度量库。
	PROCESS_DMEASURE_LIB_GLOBAL ,//按全局基准库度量库
	//PROCESS_DMEASURE_LIB_SPECIFIC,//按专门基准库度量库
};

enum{
	PROCESS_VERIFY_MODE_DEFAULT ,//按策略指定方式。
	PROCESS_VERIFY_MODE_NO_LIB ,//不验证库。
	PROCESS_VERIFY_MODE_REF_LIB ,//按全局基准库验证库
	PROCESS_VERIFY_MODE_SPECIFIC_LIB,//按专门基准库验证库
};
#pragma pack(push, 1)



struct global_control_policy{

	uint32_t be_size;
	uint32_t be_boot_measure_on;//on or not,默认值为开，关闭时不度量BIOS,直接返回成功。

	  uint32_t be_program_measure_on;//on or not，默认值为关，下载白名单后打开。进不进入钩子函数
      uint32_t be_dynamic_measure_on;//on or not

	uint32_t be_boot_control;//control or not
	  uint32_t be_program_control;//control or not 如果不在白名单中，是否放行

	//uint32_t be_policy_require_auth;
	//uint32_t be_static_reference_auth;
	//uint32_t be_dynamic_reference_auth;

//	uint32_t be_policy_auth;//none、hmac、signature
//	uint32_t be_static_reference_auth;//none、hmac、signature
//	uint32_t be_dynamic_reference_auth;//none
//	uint32_t be_auth_reference_auth;//hmac、signature

	uint32_t be_policy_replay_check;//check or not?
	uint32_t be_static_reference_replay_check;//check or not?
	uint32_t be_dynamic_reference_replay_check;//check or not?

	//uint32_t be_policy_require_process_bind;//if bind process
	//uint32_t be_static_reference_require_process_bind;//if bind process
	//uint32_t be_dynamic_reference_require_process_bind;//if bind process

	//uint32_t be_policy_require_state_bind;//if state process
	//uint32_t be_static_reference_require_state_bind;//if state process
	//uint32_t be_dynamic_reference_require_state_bind;//if state process


	//uint32_t be_process_bind_mode;//program_name,main_code,libs

	  uint32_t be_program_measure_mode;//software_measure,tcs_check,tcs_measure,auto
	  uint32_t be_measure_use_cache;//disabe enable

	  uint32_t be_dmeasure_max_busy_delay;//动态度量最大延迟（软限制）
	uint32_t be_process_dmeasure_ref_mode;//启动时采集？文件完整性库？
	uint32_t be_process_dmeasure_match_mode;//只匹配HASH，或是也路径
	  uint32_t be_program_measure_match_mode;//只匹配HASH，或是也路径
	uint32_t be_process_dmeasure_lib_mode;//是否度量库
	uint32_t be_process_verify_lib_mode;//是否度量库？文件完整性库？使用身份认证库。
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
	uint32_t be_trusted_cert_number;
	unsigned char program_reference_hash[32] ;
	unsigned char boot_reference_hash[32] ;
	unsigned char dynamic_reference_hash[32] ;
	unsigned char admin_cert_hash[32];
	unsigned char trusted_cert_hash[32];

};
struct policy_report{
	uint64_t be_nonce;
	struct policy_report_content content;
	unsigned char signiture[32];
};
#pragma pack(pop)

#endif /* TCSAPI_TCS_POLICY_DEF_H_ */
