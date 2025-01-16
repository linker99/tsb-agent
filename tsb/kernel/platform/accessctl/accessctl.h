#ifndef __HTTC_ACCESSCTL_H__
#define __HTTC_ACCESSCTL_H__

void fac_process_msg_init(void);

void fac_process_msg_set(struct task_struct *tsk, const char *fullpath,
		     const char *process_digest, int type);

void process_msg_register(void *func);
void process_msg_unregister(void *func);

#endif
