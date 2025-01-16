

#ifndef HTTCSEC_INTERCEPT_MODULE_H_
#define HTTCSEC_INTERCEPT_MODULE_H_

#include <linux/fs.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/types.h>


#define INTERCEPT_MODULE_STATUS_ENABLED 0x1


struct httcsec_intercept_module
{
	int (*bprm_check_security)(struct linux_binprm *bprm);
	int (*mmap_file)(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
	int (*kernel_module_from_file)(struct file *file);

	int (*init_module)(void __user *umod, unsigned long len, const char __user *uargs);

	int (*ptrace_access_check)(struct task_struct *child, unsigned int mode);
	int (*ptrace_traceme)(struct task_struct *parent);

	unsigned long status;
};
//exported begin
int httcsec_register_intercept_module(struct httcsec_intercept_module *intercept);
int httcsec_unregister_intercept_module(struct httcsec_intercept_module *intercept);
//exported end

int httcsec_disable_intercept_module(void);
int httsec_enalbe_intercept_module(void);

#endif /* HTTCSEC_INTERCEPT_MODULE_H_ */
