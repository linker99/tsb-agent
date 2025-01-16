

#ifndef TCSAPI_TCS_FILE_INTEGRITY_H_
#define TCSAPI_TCS_FILE_INTEGRITY_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "tcs_constant.h"
#define MAX_DELETE_NUM 1000
#define MAX_SINGLE_DELETE_NUM (MAX_DELETE_NUM/10)
//enum{
//	FILE_INTEGRITY_TYPE_HASH256,//只有程序HASH
//	FILE_INTEGRITY_TYPE_HASH256_WITH_NAME,//可包含程序HASH、路径和名称
//	//FILE_INTEGRITY_TYPE_HASH256_WITH_LIBSET,//可包含程序HASH、路径和名称,所有共享库的HASH集合
//};

#pragma pack(push, 1)

//struct file_integrity_item_extended{
//	uint8_t  flags;//extend(有扩展),开关(不是删除)，是否控制,path_not_hash
//	uint8_t  extend_size;
//	uint16_t be_path_length;
//	//uint16_t be_extend_size;
//	//uint16_t be_lib_number;
//	unsigned char data[0];// extend_data + hash  + path + name
//};

enum{
	FILE_INTEGRITY_FLAG_ENABLE = 0,
	FILE_INTEGRITY_FLAG_CONTROL,
	FILE_INTEGRITY_FLAG_FULL_PATH
};
struct file_integrity_item{
	uint8_t  flags;//开关(不是删除)，是否控制,path_not_hash
	uint8_t  extend_size;
	uint16_t be_path_length;
	unsigned char data[0];//  hash  +  extend_data + path
};



#define MAX_FILE_INTEGRITY_ITEM_SIZE \
	(sizeof(struct file_integrity_item) + \
	DEFAULT_HASH_SIZE +  (1 << 8 * sizeof(uint8_t)) +\
	MAX_PATH_LENGTH)

struct file_integrity_update{
	uint32_t be_size;
	uint32_t be_action;
	uint64_t be_replay_counter;
	//uint32_t be_item_type;
	uint32_t be_item_number;
	uint32_t be_data_length;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	unsigned char data[0];// file_integrity_item array ,every item 4 byte align
};
#pragma pack(pop)




// white list (program reference) interface
/*
 * 	读取基准库
 */
int tcs_get_file_integrity(struct file_integrity_item **references, int *num, int *length);//proc 导出



/*
 * 	更新文件完整性基准库
 * 	设置、增加、删除。
 */

int tcs_update_file_integrity(
		struct file_integrity_update *references,
		const char *uid,int auth_type,
		int auth_length,unsigned char *auth);


///*
// * 	通过HASH查找程序基准库
// */
//
//int tcs_get_file_integrity_by_hash(
//		struct file_integrity_item ** pp,int *num,
//		const unsigned char *hash, int hash_length);
//
/////*
//// * 	通过名字查找程序基准库
//// */
////int tcs_get_file_integrity_by_name(
////		int *num,struct file_integrity_item_user ** pp,
////		const unsigned char *name, int path_length);
//
///*
// * 	通过路径查找基准库
// */
//int tcs_get_file_integrity_by_path(
//		int *num,struct file_integrity_item **pp,
//		const unsigned char *path, int name_length);

/*
 * 	基准库匹配
 */
int tcs_match_file_integrity(const unsigned char *hash, int hash_length);
/*
 * 	基准库按路径名匹配
 */
int tcs_match_file_integrity_by_path(
		const unsigned char *hash, int hash_length,
		const unsigned char *path, int path_length);


/*
 *  +  拦截度量
 */



///*
// * 	基准库按名字名匹配
// */
//int tcs_match_file_integrity_by_name(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length);
/*
 * 	基准库按名字和路径匹配
 */
//int tcs_match_file_integrity_by_name_and_path(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length,
//		const unsigned char *path, int path_length);

/*
 *	获取基准库有效条数
 */
int tcs_get_file_integrity_valid_number (int *num);//proc 导出

/*
 * 	获取基准库存储条数
 */
int tcs_get_file_integrity_total_number (int *num);//proc 导出

/*
 *	获取基准库可增量修改限制
 */
int tcs_get_file_integrity_modify_number_limit (int *num);//proc 导出

#endif /* TCSAPI_TCS_FILE_INTEGRITY_H_ */
