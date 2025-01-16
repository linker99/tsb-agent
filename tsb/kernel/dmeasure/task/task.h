#ifndef __TASK_H
#define __TASK_H

int task_init(void);
void task_exit(void);
rwlock_t* get_tasklist_lock(void);

#endif
