

#ifndef TCSAPI_TCS_LICENSE_DEF_H_
#define TCSAPI_TCS_LICENSE_DEF_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#define MAX_CLIENT_ID_SIZE 	32


struct license_param{
	uint32_t license_type;
	uint32_t shelf_life;	//有效天数
	uint32_t client_id_length;
	uint32_t host_id_length;
	unsigned char client_id[MAX_CLIENT_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
};

struct license_arg{
	uint32_t license_type;
};

enum{
	LICENSE_ATTR_ALL = 0,
	LICENSE_ATTR_TPCM,
	LICENSE_ATTR_TSB,
	LICENSE_ATTR_TERM,
	LICENSE_ATTR_RESERVED,
	LICENSE_ATTR_MAX
};

enum{
	LICENSE_LTYPE_TEST = 1,
	LICENSE_LTYPE_OFFICIAL,
	LICENSE_LTYPE_MAX
};

#pragma pack(push, 1)
struct license_req{
	uint32_t be_license_type;
	uint32_t be_shelf_life;	//有效天数
	uint32_t be_client_id_length;
	uint32_t be_tpcm_id_length;
	uint32_t be_host_id_length;
	uint32_t be_ekpub_length;
	uint32_t be_signature_size;
	uint64_t be_time_stamp;
	unsigned char client_id[MAX_CLIENT_ID_SIZE];
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
	unsigned char ekpub[MAX_EK_PUBKEY_SIZE];
	unsigned char signature[0];////AIK 签名
};
//#define MAX_CLIENT_ID_SIZE 	128
struct license{

	uint32_t be_license_type;
	uint32_t be_client_id_length;
	uint32_t be_tpcm_id_length;
	uint32_t be_host_id_length;
	uint32_t be_ekpub_length;
	uint32_t be_signature_size;
	uint64_t be_time_stamp;
	uint64_t be_deadline;
	uint64_t be_time_end;
	unsigned char client_id[MAX_CLIENT_ID_SIZE];
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
	unsigned char ekpub[MAX_EK_PUBKEY_SIZE];
	unsigned char signature[0];//华泰签名

};

typedef struct license_entity{
	uint32_t be_license_type;
	uint32_t be_client_id_length;
	uint32_t be_tpcm_id_length;
	uint32_t be_host_id_length;
	uint64_t be_time_stamp;
	uint64_t be_deadline;
	uint64_t be_time_end;
	unsigned char client_id[MAX_CLIENT_ID_SIZE];
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char host_id[MAX_HOST_ID_SIZE];
}license_entity_st;

#pragma pack(pop)


#endif /* TCSAPI_TCS_LICENSE_DEF_H_ */
