#ifndef __PROCESS_IDENTITY_H
#define __PROCESS_IDENTITY_H

int process_identity_init(void);
void process_identity_exit(void);

int get_process_identity(unsigned char *process_name,int *process_name_length);
int is_role_member(const unsigned char *role_name);

void remove_current_task_ids_cache(struct task_struct *tsk);

#endif
