#ifndef __HTTC_TCF_H__
#define __HTTC_TCF_H__

enum{
	TCF_SEM_INDEX_POLICY,
	TCF_SEM_INDEX_INTEGRITY,
	TCF_SEM_INDEX_LOG,
	TCF_SEM_INDEX_MAX,
};

int tcf_util_sem_val (int index);
int tcf_util_sem_get (int index);
void tcf_util_sem_release (int index);

#endif	/** __HTTC_TCF_H__ */

