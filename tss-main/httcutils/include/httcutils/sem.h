#ifndef __HTTCUTILS_SEM_H__
#define __HTTCUTILS_SEM_H__

#include <sys/types.h>

/** 信号量赋初值 */
int httc_util_sem_init (int semid, int semnum, int value);

/** 获取信号量当前值 */
int httc_util_sem_val (int id, int snum);

/** 获取信号量 */
int httc_util_sem_p (int id, int snum);

/** 释放信号量 */
void httc_util_sem_v (int id, int snum);

/**
	创建一个信号量信号量
	若不存在，则新建；若已存在，则返回直接打开
*/
int httc_util_semget (key_t key, int nsems);

/**
	创建一个信号量信号量集，每个信号量初始化值为1
	若不存在，则新建；若已存在，则返回直接打开
*/
int httc_util_semget_single (key_t key, int nsems);

#endif	/** __HTTCUTILS_SEM_H__ */
