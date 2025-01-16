

#ifndef TCSAPI_TCS_CONSTANT_H_
#define TCSAPI_TCS_CONSTANT_H_

#include <linux/limits.h>

#define DEFAULT_HASH_SIZE 		32
#define MAX_TPCM_ID_SIZE 		32
#define MAX_HOST_ID_SIZE 		32
#define MAX_EK_PUBKEY_SIZE 		64
#define DEFAULT_PCR_SIZE 		32
#define DEFAULT_SIGNATURE_SIZE  64
#define MAX_PATH_LENGTH 		PATH_MAX	//涓�鑸负4096
#define MAX_NAME_LENGTH 		NAME_MAX	//涓�鑸负255
#define MAX_PROCESS_NAME_LENGTH 64
#define SM4_KEY_SIZE    		16
#define SM4_IV_SIZE                 16
#define SM2_PRIVATE_KEY_SIZE    32
#define SM2_PUBLIC_KEY_SIZE     64

#define MAX_KEY_NAME_SIZE 	128
#define MAX_NV_NAME_SIZE 	256

enum{
	POLICY_ACTION_SET,
	POLICY_ACTION_ADD,//or grant
	POLICY_ACTION_DELETE,
	POLICY_ACTION_MODIFY//有限制
};

#define HTTC_TSS_CONFIG_PATH	"/usr/local/httcsec/conf/"
#define HTTC_TSB_CONFIG_PATH	"/usr/local/httcsec/log/"

#if defined platform_2700
#define TCS_PROCESS_IDS_PATH 	HTTC_TSS_CONFIG_PATH"process_ids.data"
#define TCS_PROCESS_ROLES_PATH	HTTC_TSS_CONFIG_PATH"process_roles.data"
#endif
#endif /* TCSAPI_TCS_CONSTANT_H_ */
