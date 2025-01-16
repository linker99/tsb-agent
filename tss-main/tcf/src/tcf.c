#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>

#include "httcutils/sem.h"
#include "httcutils/debug.h"
#include "tcfapi/tcf_error.h"
#include "tcf.h"

#define SEM_KEY_TCF			0x9999

static int sem_id = -1;

int tcf_util_sem_val (int index)
{
	return httc_util_sem_val (sem_id, index);
}
int tcf_util_sem_get (int index)
{
	int r = -1;
	if ((r = httc_util_sem_p (sem_id, index))){
		httc_util_pr_error ("httc_util_sem_p[%d] error: %d\n", index, r);
		return (r == EAGAIN) ? TCF_ERR_SEM_TIMEOUT : TCF_ERR_SEM;
	}
	return TCF_SUCCESS;
}
void tcf_util_sem_release (int index)
{
	httc_util_sem_v (sem_id, index);
}

int __tcf_init(void) __attribute__((constructor));
void __tcf_deinit(void) __attribute__((destructor));

int __tcf_init(void)
{
	sem_id = httc_util_semget_single (SEM_KEY_TCF, TCF_SEM_INDEX_MAX);
	if (sem_id < 0){
		httc_util_pr_error ("httc_util_semget_single error: %d\n", sem_id);
		return -1;
	}
	return 0;
}

void __tcf_deinit(void)
{
	return ;
}

/**
int main ()
{
	int i = 20;
	int r = -1;
	
	sem_id = httc_util_semget_single (TCF_SEM_KEY_TCF, TCS_SEM_INDEX_MAX);
	if (sem_id < 0){
		printf ("tcf_util_sem_init error: %d\n", sem_id);
		return -1;
	}

	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_POLICY))){
		printf ("tcf_util_sem_policy_get error: %d\n", r);
		return r;
	}
	while (i--){
		printf ("i: %d\n", i);
		sleep (1);
	}
	tcf_util_sem_release ();

	if((semctl(sem_id, 0, IPC_RMID))<0){
		perror("semctl IPC_RMID");
		exit(-1);
	}

	return 0;
}
*/
