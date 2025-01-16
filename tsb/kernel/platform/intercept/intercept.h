

#ifndef HTTCSEC_intercept_H_
#define HTTCSEC_intercept_H_
#include <linux/version.h>
#include <linux/security.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "intercept_module.h"

#ifdef __cplusplus
extern "C" {
#endif

int intercept_bprm_check_security(struct linux_binprm *bprm);
int intercept_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
int intercept_kernel_module_from_file(struct file *file);

int intercept_init_module(void __user *umod, unsigned long len, const char __user *uargs);

int intercept_ptrace_access_check(struct task_struct *child, unsigned int mode);
int intercept_ptrace_traceme(struct task_struct *parent);

#ifdef __cplusplus
}
#endif

#endif /* HTTCSEC_intercept_H_ */
