

#ifndef TCFAPI_TCF_BMEASURE_H_
#define TCFAPI_TCF_BMEASURE_H_

#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_kernel_def.h"

#define MAX_BOOT_HASH_VERSION_NUMBER 8
#define MAX_BOOT_EXTERN_SIZE 	255

#define MAX_BOOT_REFERENCE_ITEM_SIZE\
	(sizeof (struct boot_ref_item) + DEFAULT_HASH_SIZE * MAX_BOOT_HASH_VERSION_NUMBER + MAX_BOOT_EXTERN_SIZE + MAX_PATH_LENGTH)

struct boot_references_update;

struct boot_ref_item_user{
	int hash_length;
	int hash_number;
	int stage;
	int is_control;//bool
	int is_enable;//bool
	char *hash;//hash_length *hash_number
	char *name;
	int extend_size;
	char *extend_buffer;
};

struct boot_measure_record_user{
	int hash_length;
	int stage;
	uint32_t result;
	uint64_t measure_time;
	char  hash[DEFAULT_HASH_SIZE];
	char *name;
};

/*
 * 	准备更新启动度量启动基准库
 */

int tcf_prepare_update_boot_measure_references(
		const struct boot_ref_item_user *references,int num,
		unsigned char *tpcm_id,int tpcm_id_length,
		int action,	uint64_t replay_counter,
		struct boot_references_update **obuffer,int *olen);

// boot measure reference interface
/*
 * 	更新启动度量基准库
 * 	设置。
 */

int tcf_update_boot_measure_references(struct boot_references_update *references,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth);
/*
 * 	获取启动度量基准库
 */
int tcf_get_boot_measure_references(struct boot_ref_item_user **references,int *num);//proc 导出

/*
 * 	释放启动基准库内存。
 */
void tcf_free_boot_measure_references(struct boot_ref_item_user *references,int num);

/*
 * 	获取启动度量记录（采集值）
 */

int tcf_get_boot_measure_records(struct  boot_measure_record_user **boot_records,int *num);

/*
 * 	释放启动记录内存。
 */

void tcf_free_boot_measure_records(struct  boot_measure_record_user *boot_records,int num);

/*
 * 	启动度量
 */

int tcf_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen);

/*
 *	简易启动度量
 */
int tcf_simple_boot_measure (uint32_t stage, uint8_t* digest, uint8_t *obj, uint32_t objLen);



#endif /* TCFAPI_TCF_BMEASURE_H_ */
