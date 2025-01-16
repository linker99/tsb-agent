/*
 * file_integrity.h
 *
 *  Created on: 2021年4月21日
 *      Author: wangtao
 */

#ifndef SRC_FILE_INTEGRITY_H_
#define SRC_FILE_INTEGRITY_H_
#include "tcsapi/tcs_file_integrity.h"
struct file_integrity_item;
struct file_integrity_item_info{
	unsigned int size;
	unsigned int aligned_size;
	unsigned int path_length;
	unsigned int offset;
	struct file_integrity_item data;
};
typedef int (*file_integrity_func)(struct file_integrity_item_info *info,void *context);
//int file_integrity_add_policy_data(char *buffer,int length,struct file_integrity_item **phead);
int file_integrity_hash_policy_data(
		char *buffer,unsigned int length,
		struct file_integrity_item ***parray,
		unsigned int *ptotal,unsigned int *pvalid);
int file_integrity_check(struct file_integrity_item *item,unsigned int size);
int file_integrity_iterator(int from,int number,file_integrity_func func,void *context);
unsigned int file_integrity_valid(void);
unsigned int file_integrity_total(void);
unsigned int file_integrity_modify_limit(void);
void file_integrity_reset(void);
void file_integrity_clear_list(struct file_integrity_item *item);
int file_integrity_delete_policy_data_prepare(char *buffer,unsigned int length,
		struct file_integrity_item_info ***dellist,unsigned int *delnum);
int file_integrity_delete_policy_data(
		struct file_integrity_item_info **dellist,unsigned int del_num);
void file_integrity_delete_from_hashtable_array(
		struct file_integrity_item **item,unsigned int num);
void file_integrity_append_hashed_array(
		struct file_integrity_item **item,unsigned int total,
		unsigned int valid,	unsigned int data_length);
#endif /* SRC_FILE_INTEGRITY_H_ */
