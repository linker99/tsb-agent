#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

union semun {
	int              val;    /* Value for SETVAL */
	struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
	unsigned short  *array;  /* Array for GETALL, SETALL */
	struct seminfo  *__buf;  /* Buffer for IPC_INFO (Linux-specific) */
};

int httc_util_sem_init (int semid, int semnum, int value)
{
	union semun v;
	v.val = value;
	return semctl (semid, semnum, SETVAL, v);
}

int httc_util_sem_val (int id, int snum)
{
	return semctl (id, snum, GETVAL);
}

/** 获取信号量 */
int httc_util_sem_p (int id, int snum)
{
	int r = 0;
	struct sembuf op;
	struct timespec timeout = {
		.tv_sec = 600,	//10min
		.tv_nsec = 0
	};
	if (id < 0){
		printf ("[%s:%d] sem_id: %d\n", __func__, __LINE__, id);
		return -1;
	}

	op.sem_num = snum;
	op.sem_op = -1;
	op.sem_flg = SEM_UNDO;
	r = semtimedop (id, &op, 1, &timeout);
	if (r == -1){
		printf ("[%s:%d] semtimedop error: %s\n", __func__, __LINE__, strerror (errno));
 	}
	return r ? errno : 0;
}

/** 释放信号量 */
void httc_util_sem_v (int id, int snum)
{
	struct sembuf op;
	if (id < 0)	return ;
	op.sem_num = snum;
	op.sem_op = 1;
	op.sem_flg = SEM_UNDO;
	semop (id, &op, 1);
	return ;
}

/**
	创建一个信号量集
	若不存在，则新建；若已存在，则返回直接打开
*/
int httc_util_semget (key_t key, int nsems)
{
	int sem_id = -1;
	sem_id = semget (key, nsems, IPC_CREAT|IPC_EXCL|0666);
	if ((sem_id == -1) && (errno == EEXIST)){
		sem_id = semget (key, nsems, IPC_CREAT|0666);
		if (sem_id == -1){
			printf ("[%s:%d] sem_id_tcf get error: %s\n", __func__, __LINE__, strerror (errno));
		}
	}
	return sem_id;
}

/**
	创建一个信号量集，每个信号量初始化值为1
	若不存在，则新建；若已存在，则返回直接打开
*/
int httc_util_semget_single (key_t key, int nsems)
{
	int i,r;
	int sem_id = -1;

	sem_id = semget (key, nsems, IPC_CREAT|IPC_EXCL|0666);
	if ((sem_id == -1) && (errno == EEXIST)){
		sem_id = semget (key, nsems, IPC_CREAT|0666);
		if (sem_id == -1){
			printf ("[%s:%d] sem_id_tcf get error: %s\n", __func__, __LINE__, strerror (errno));
		}
		return sem_id;
	}

	if (sem_id != -1){
		for (i = 0 ; i < nsems; i++){
			if ((r = httc_util_sem_init (sem_id, i, 1))){
				printf ("httc_util_sem_init error: %d\n", r);
				return r;
			}
		}
	}

	return sem_id;
}


