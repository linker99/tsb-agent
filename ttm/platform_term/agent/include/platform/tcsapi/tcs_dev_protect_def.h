
#ifndef TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_DEF_H_
#define TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_DEF_H_
#include <stdint.h>

#define FILE_DEV_POLICY_PATH 			HTTC_TSS_CONFIG_PATH"cdrom_config.data"

#pragma pack(push, 1)
struct cdrom_protect_item{
	uint32_t flags;  // 1: 包含，  0:不保护
};

struct cdrom_protect_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// cdrom_protect_item array
};
#pragma pack(pop)


#endif /* TRUNK_INCLUDE_TCSAPI_TCS_DEV_PROTECT_DEF_H_ */
