

#ifndef HOOK_H_
#define HOOK_H_


#include <asm/atomic.h>
//extern struct security_operations *hook_default_security_ops;
//extern struct security_operations *hook_old_security_ops;

int hook_init(void);
void hook_exit(void);

//int hook_replace_system_call(int num, unsigned long *syscall, unsigned long **old_call_holder);
int hook_replace_system_call(int num, unsigned long *syscall, unsigned long **old_call_holder);
int hook_restore_system_call(int num, unsigned long *syscall, unsigned long **old_call_holder);

/* replace address of kernel rodata or data segment */
int hook_search_ksym(const char * sym_name, unsigned long *address);
unsigned long hook_replace_pointer(void **pp_addr, void *ponter);
unsigned long hook_replace_area(unsigned long addr, void *ponter, int size);

#endif /* HOOK_H_ */
