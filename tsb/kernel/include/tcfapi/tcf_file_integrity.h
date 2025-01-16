

#ifndef TCFAPI_TCF_FILE_INTEGRITY_H_
#define TCFAPI_TCF_FILE_INTEGRITY_H_
#include <stdint.h>
#include "../tcsapi/tcs_constant.h"

struct file_integrity_update;


struct file_integrity_item_user{
	unsigned int hash_length;
	unsigned int path_length;
	int is_control;//是否进行控制
	int is_enable;//是否启用
	int is_full_path;//bool
	unsigned int extend_size;
	char *hash;
	char *path;
	char *extend_buffer;
	//const unsigned char *lib_hashs;
};

struct file_integrity_sync {
	uint64_t smajor;	/** 主版本号 */
	uint32_t sminor;	/** 次版本号 */
	uint32_t length;	/** 白名单长度 */
	uint32_t action;	/** ACTION */
	uint8_t *data;		/** 白名单 */
};

struct sync_version{
	uint64_t smajor;	/** 起始主版本号 */
	uint32_t sminor;	/** 起始次版本号 */
	uint64_t emajor;	/** 终止主版本号 */
	uint32_t eminor;	/** 终止次版本号 */
};

// white list (program reference) interface
/*
 * 	读取基准库
 */
int tcf_get_file_integrity(struct file_integrity_item_user **references,
		unsigned int from,unsigned int *inout_num);//proc 导出

/*
 * 	准备更新基准库。
 */
int tcf_prepare_update_file_integrity(
		struct file_integrity_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct file_integrity_update **buffer,unsigned int *prepare_size);

/*
 * 	更新文件完整性基准库
 * 	设置、增加、删除。
 */

int tcf_update_file_integrity(
		struct file_integrity_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth,
		unsigned char *local_ref, unsigned int local_ref_length);

/*
 *	释放基准库内存
 */
void tcf_free_file_integrity(struct file_integrity_item_user * pp,unsigned int num);
///*
// * 	通过HASH查找程序基准库
// */
//int tcf_get_file_integrity_by_hash(
//		struct file_integrity_item_user ** pp,int *num,
//		const unsigned char *hash, int hash_length);

///*
// * 	通过名字查找程序基准库
// */
//int tcf_get_file_integrity_by_name(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *name, int path_length);

///*
// * 	通过路径查找基准库
// */
//int tcf_get_file_integrity_by_path(
//		int *num,struct file_integrity_item_user ** pp,
//		const unsigned char *path, int path_length);


///*
// * 	基准库按名字名匹配
// */
//int tcf_match_file_integrity_by_name(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length);
///*
// * 	基准库按名字和路径匹配
// */
//int tcf_match_file_integrity_by_name_and_path(
//		const unsigned char *hash, int hash_length,
//		const unsigned char *name, int name_length,
//		const unsigned char *path, int path_length);
/*
 *	获取基准库有效条数
 */

int tcf_get_file_integrity_valid_number ( int *num);//proc 导出
/*
 * 	获取基准库存储条数
 */
int tcf_get_file_integrity_total_number (int *num);//proc 导出

/*
 *	获取基准库可增量修改限制
 */
int tcf_get_file_integrity_modify_number_limit (int *num);//proc 导出


/*
 * 获取文件完整性同步数据
 */
int tcf_get_synchronized_file_integrity (struct sync_version *version, struct file_integrity_sync **file_integrity, int *num);

/*
 * 释放文件完整性同步数据
 */
int tcf_free_synchronized_file_integrity (struct file_integrity_sync **file_integrity, int num);

/*
 * 	准备更新关键文件完整性基准库。
 */
int tcf_prepare_update_critical_file_integrity(
		struct file_integrity_item_user *items, unsigned int num,
		unsigned char *tpcm_id, unsigned int tpcm_id_length,
		int action, uint64_t replay_counter,
		struct file_integrity_update **buffer, unsigned int *prepare_size);

/*
 * 	整体更新关键文件完整性基准库
 */
int tcf_update_critical_file_integrity(
		struct file_integrity_update *references,
		const char *uid, int cert_type,
		unsigned int auth_length, unsigned char *auth);

/** 获取关键更新基准库 */
int tcf_get_critical_file_integrity (
		struct file_integrity_item_user **references, unsigned int *num);

/** 释放关键更新基准库内存 */
void tcf_free_critical_file_integrity (
		struct file_integrity_item_user *references, unsigned int num);


/*
 *	获取文件完整性库hash
 */
int tcf_get_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len);

/** 获取关键文件完整性基准库摘要值 */
int tcf_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len);

#endif /* TCFAPI_TCF_FILE_INTEGRITY_H_ */
