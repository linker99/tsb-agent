

#ifndef TCSAPI_TCS_STORE_DEF_H_
#define TCSAPI_TCS_STORE_DEF_H_
#include "tcs_constant.h"

#pragma pack(push,1) 
struct nv_info{
	uint32_t index;
	int size;
	struct auth_policy auth_policy;
	char name[MAX_NV_NAME_SIZE];
};
#pragma pack(pop)

#endif 

