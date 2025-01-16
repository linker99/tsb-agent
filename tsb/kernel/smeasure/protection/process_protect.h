#ifndef __HTTC_PROCESS_PROTECT_H__
#define __HTTC_PROCESS_PROTECT_H__
#define PROCESS_MAX_NUM 0x10

int httc_process_protect_init(void);
void httc_process_protect_exit(void);
int is_protect_task(struct task_struct *p);
void process_protection_conf_notify_func(int status);

#endif	/* __HTTC_PROCESS_PROTECT_H__ */

