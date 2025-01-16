
#ifndef TCS_FILE_PROTECT_DEF_H_
#define TCS_FILE_PROTECT_DEF_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include "tcs_constant.h"


#define FILE_PROTECT_POLICY_PATH 			HTTC_TSS_CONFIG_PATH"file_protect.data"

enum {
	FILE_WRITE_PROTECT = 0,
	FILE_READ_PROTECT
};
enum {//BIT OPERATE
	FILE_PROTECT_MEASURE_ENV = 1,
	FILE_PROTECT_MEASURE_PROCESS=2,//
	//FILE_PROTECT_MEASURE_FILE=4//must be a critical file,
};

enum{
	PRIVI_ALL,
	PRIVI_READ_ONLY
};
#pragma pack(push, 1)
struct file_protect_privileged_process{
	uint32_t be_privi_type;//ALL ,READ_ONLY
	unsigned char path[256];// 0 terninated
	unsigned char hash[32];
};
struct file_protect_item{
	uint8_t measure_flags;
	uint8_t type;//wirte_protect,read_protect
	uint16_t be_privileged_process_num;
	unsigned char path[256];///path[path_length]    (0 terminated and fill to 4x byte boundary)
	struct file_protect_privileged_process privileged_processes[0];// (4 byte align)
};

struct file_protect_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// file_protect_item array
};
#pragma pack(pop)




#endif /* TCS_FILE_PROTECT_DEF_H_ */
