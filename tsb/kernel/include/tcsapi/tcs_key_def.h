

#ifndef TCSAPI_TCS_KEY_DEF_H_
#define TCSAPI_TCS_KEY_DEF_H_
#include <stdint.h>
#include "tcs_constant.h"
#include "../tcsapi/tcs_auth_def.h"

#pragma pack(push,1) 

struct key_info {
	int key_type;
	int key_use;
	int origin;
	int key_size;
	int migratable;
	int attribute;
};

struct sealed_data_info {
	int size;
};

enum {
	KEY_NODE_TYPE_KEY, KEY_NODE_TYPE_SEALED_DATA
};
	
struct key_node {
	unsigned char name[MAX_KEY_NAME_SIZE];
	union {
		struct sealed_data_info seal_data;
		struct key_info key;
	};
	struct auth_policy policy;
	int children_number;
	struct key_node *children[0];
};

#pragma pack(pop)

#endif 

