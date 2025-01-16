/*
 * HTTCUTILS_FILE.h
 *
 *  Created on: Sep 16, 2014
 *      Author: wangtao
 */

#ifndef HTTCUTILS_FILE_H_
#define HTTCUTILS_FILE_H_

#ifdef __cplusplus
extern "C" {
#endif
struct file_section{
	unsigned long offset;
	unsigned length;
	const char *buffer;
};
int httc_util_file_write(const char* filename,const char *buffer,unsigned int size);
int httc_util_file_write_offset(const char* filename,const char *buffer,unsigned long offset,unsigned int size);
int httc_util_file_write_offset_array(const char* filename,struct file_section *p,int n);
int httc_util_file_append(const char* filename,const char *buffer,unsigned int size);
void* httc_util_file_read_full(const char* filename,unsigned long *psize);
void *httc_util_file_read_offset(const char* filename,unsigned long offset,unsigned long *size);
int httc_util_file_copy_file(const char* source,const char* target);
int httc_util_file_size(const char* filename,unsigned long *psize);
int httc_util_create_path (const char *path);
int httc_util_create_path_of_fullpath (const char *fullpath);

//int mutex_lock(int sem_id);
//int mutex_unlock(int fd);
//void mutex_free(int sem_id);

#ifdef __cplusplus
}
#endif

#endif /* HTTCUTILS_FILE_H_ */
