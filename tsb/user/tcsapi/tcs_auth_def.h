

#ifndef TCSAPI_TCS_AUTH_DEF_H_
#define TCSAPI_TCS_AUTH_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"

#define TPCM_UID_MAX_LENGTH 32
#define MAX_CERT_NUM 11
enum{
	ADMIN_AUTH_POLICY_CERT_ONLY = 0,//只允许证书认证，与无这条策略相同
	ADMIN_AUTH_POLICY_POLICY_ONLY,//只允许策略认证
	ADMIN_AUTH_POLICY_OR_CERT,//策略或者证书认证任何一个满足
	ADMIN_AUTH_POLICY_AND_CERT//策略与证书认证同时满足
};

enum{
	CERT_TYPE_NONE,//用于无认证，只用于策略
	CERT_TYPE_PUBLIC_KEY_SM2,//128 位SM2公钥
	CERT_TYPE_PASSWORD_32_BYTE,//最长32字节密码，认证时计算HMAC
	CERT_TYPE_X501_SM2,//X501 国密证书
};
#define POLICY_FLAG_TRUST_STATE (1 << 0)//拆分
//#define POLICY_FLAG_MIGRATABLE (1 << 1)
//#define POLICY_FLAG_TSB (1 << 2)
#define POLICY_FLAG_PROCESS_IDENTITY (1 << 3)
#define POLICY_FLAG_PROCESS_ROLE (1 << 4)
#define POLICY_FLAG_USER_ID (1 << 5)
#define POLICY_FLAG_GROUP_ID (1 << 6)

#define POLICY_FLAG_TRUST_BOOT (1 << 7 )//拆分
#define POLICY_FLAG_TRUST_DMEASURE (1 << 8 )//拆分
#define POLICY_FLAG_TRUST_APP_LOAD (1 << 9 )//拆分
#define POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE (1 << 10 )//拆分
#define POLICY_FLAG_TRUST_BOOTLOADER (1 << 11 )//拆分
//#define POLICY_FLAG_TRUST_INIT_ROOT (1 << 12 )//拆分
#define POLICY_FLAG_TRUST_KERNEL (1 << 13 )//拆分
//#define POLICY_FLAG_TRUST_BOOT_CONFIG (1 << 14 )//拆分
#define POLICY_FLAG_USED_PASSWD (1 << 15 )//拆分
#define POLICY_FLAG_ENV (1 << 16 )//拆分


#define MAX_ADMIN_CERT_NUMBER 8
#define MAX_CERT_SIZE 64

//tpcm策略认证管理对象
enum{
	TPCM_ADMIN_AUTH_POLICY_BOOT_REF = 1,
	TPCM_ADMIN_AUTH_POLICY_INTEGRETY_REF,
	TPCM_ADMIN_AUTH_POLICY_DYNAMIC_REF,
	TPCM_ADMIN_AUTH_POLICY_MAX
};

#pragma pack(push, 1)

struct admin_auth_policy{
	uint32_t be_object_id;
	uint32_t be_admin_auth_type;
	uint32_t be_policy_flags;
	uint32_t be_user_or_group;
	unsigned char process_or_role[MAX_PROCESS_NAME_LENGTH];
};

struct admin_auth_policy_update{
	uint32_t be_number;
	uint32_t be_action;
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct admin_auth_policy policies[0];//admin_cert_item
};

struct admin_cert_item{
	uint32_t be_cert_type;
	uint32_t be_cert_len;
	unsigned char name[TPCM_UID_MAX_LENGTH];
	unsigned char data[MAX_CERT_SIZE];
};

struct admin_cert_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct admin_cert_item cert;//admin_cert_item
};

#pragma pack(pop)

struct auth_policy{
	unsigned int policy_flags;
	unsigned char *process_or_role;
	unsigned int user_or_group;
	unsigned char *password;
};

#endif /* TCSAPI_TCS_AUTH_DEF_H_ */
