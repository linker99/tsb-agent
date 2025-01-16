

#ifndef TCSAPI_TCS_PROCESS_DEF_H_
#define TCSAPI_TCS_PROCESS_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
//#include "tcs_constant.h"
#define MAX_ROLE_NAME_LENGTH 128

#pragma pack(push, 1)
struct role_member{
	uint8_t length;
	unsigned char name[0];
};
struct process_role{
	uint32_t be_name_length;
	uint32_t be_members_length;
	uint32_t be_members_number;
	//unsigned char name[MAX_ROLE_NAME_LENGTH];
	unsigned char members[0];//name + list of struct role_member;

};
/*
 * 进程身份重复规则，进程身份主程序的HASH不允许重，
 * 同一个名字可以有不同的主HASH（支持多个版本）
 */
struct process_identity{
	uint8_t  name_length;
	uint8_t  specific_libs;
	uint16_t be_hash_length;
	uint16_t be_lib_number;
	unsigned char data[0];//  hash[1 + lib_number]  +  name
};


#pragma pack(pop)
#endif /* TCSAPI_TCS_PROCESS_DEF_H_ */
