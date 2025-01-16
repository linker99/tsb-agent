

int hook_replace_system_call(int num, unsigned long *new_call, unsigned long **old_call);
int hook_restore_system_call(int num, unsigned long *new_call, unsigned long **old_call);

int httc_syscall_init(void);
void httc_syscall_exit(void);
