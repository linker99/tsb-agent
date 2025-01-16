/*
 * tcs_auth_def.h
 *
 *  Created on: 2021年4月13日
 *      Author: wangtao
 */

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
#define KEY_ID_LEN 32
#define KEY_LEN 64
#define EK_INDEX 2
#define CERT_AUTH_LEN 64
#define UID_LEN_OFFSET 12
#define AUTH_LEN_OFFSET 20
#define UPDATE_NUM_OFFSET 72
#define CERT_LEN_OFFSET 24
#define DATA_LEN_OFFSET 4
#define MAX_CMD_LEN 2048
#define LIMIT_CMD_SIZE (512*1024)	/** 512K */
#define BASE_DATA_LEN 76

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

#define POLICY_PCR \
		(POLICY_FLAG_TRUST_STATE\
		|POLICY_FLAG_TRUST_BOOT\
		|POLICY_FLAG_TRUST_DMEASURE\
		|POLICY_FLAG_TRUST_APP_LOAD\
		|POLICY_FLAG_TRUST_BOOTLOADER\
		|POLICY_FLAG_TRUST_BIOS_OR_FIRMWARE\
		|POLICY_FLAG_TRUST_KERNEL)

#define MAX_ADMIN_CERT_NUMBER 8
#define MAX_CERT_SIZE 64
#define MAX_CERT_NEW_SIZE 2048

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

struct root_cert_item{
	uint32_t be_cert_type;
	uint32_t be_cert_len;
	unsigned char data[MAX_CERT_NEW_SIZE];
};

struct root_cert_update{
	uint32_t be_size;
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	struct root_cert_item cert;
};


struct root_cert_update_vir{
	uint32_t be_size;
	uint64_t be_replay_counter;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	uint32_t be_type; //证书类型 证书链类型 priv x509两种，两种类型不能同时存在
	uint32_t be_num; //证书个数
	struct root_cert_item cert[0];
};

struct root_cert_item_vir{
	uint32_t be_cert_type;
	uint32_t be_cert_len;
	char data[8];
};
#pragma pack(pop)
struct auth_policy{
	unsigned int policy_flags;
	unsigned char *process_or_role;
	unsigned int user_or_group;
	unsigned char *password;
};

#endif /* TCSAPI_TCS_AUTH_DEF_H_ */
