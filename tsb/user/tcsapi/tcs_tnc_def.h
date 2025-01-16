

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
	uint32_t be_protocol;//协议：udp or tcp
	uint32_t be_remote_ip;//对端IP,0表示任何
	uint32_t be_local_ip;//本机IP,0表示任何
	uint16_t be_remote_port;//对端端口,0表示任何
	uint16_t be_local_port;//本地端口,0表示任何

};
struct tnc_policy{
	uint32_t be_exception_number;//例外的数量	
	uint16_t be_server_port;//管理中心端口
	uint16_t be_control_mode;//控制模式：默认全控制、默认不控制
	uint8_t  encrypt_auth;//要求报文加密认证
	uint8_t  server_testify;//要求附加管理中心证实（对端可信状态）
	uint8_t  report_auth_fail;//向管理中心汇报可信认证失败
	uint8_t  report_session;//向管理中心汇报会话建立、过期、删除
	uint32_t be_session_expire;//会话过期时间（分钟），0不过期
	uint32_t be_server_ip;//管理中心IP地址
	struct tnc_policy_item exceptions[0];//例外数组
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
