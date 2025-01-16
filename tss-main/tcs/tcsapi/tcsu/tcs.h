#ifndef __HTTC_TCS_H__
#define __HTTC_TCS_H__

enum{
	TCS_SEM_INDEX_KEY,
	TCS_SEM_INDEX_NV,
	TCS_SEM_INDEX_POLICY,
	TCS_SEM_INDEX_MAX,
};

int tcs_util_sem_val (int index);
int tcs_util_sem_get (int index);
void tcs_util_sem_release (int index);

#endif	/** __HTTC_TCS_H__ */
 
