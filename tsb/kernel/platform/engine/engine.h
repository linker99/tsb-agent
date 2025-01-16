#ifndef __ENGINE_H
#define __ENGINE_H

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/utsname.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/kernel_read_file.h>
#endif
#include "../../include/version.h"

struct httcsec_intercept_module 
{
	int (*bprm_check_security) (struct linux_binprm *bprm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	int (*mmap_file) (struct file * file, unsigned long reqprot,
			  unsigned long prot, unsigned long flags);
#else
	int (*file_mmap) (struct file * file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags, unsigned long addr,
			  unsigned long addr_only);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	int (*kernel_read_file) (struct file * file, 
				enum kernel_read_file_id id, bool contents);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	int (*kernel_read_file) (struct file * file,
				 enum kernel_read_file_id id);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	int (*kernel_module_from_file) (struct file * file);
#endif

	int (*init_module) (void __user * umod, unsigned long len,
			    const char __user * uargs);

	/* int (*file_permission) (struct file * file, int mask); */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
	int (*file_open)(struct file *file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	int (*file_open)(struct file *file, const struct cred *cred);
#else
	int (*dentry_open)(struct file *file, const struct cred *cred);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
	int (*task_kill)(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	int (*task_kill)(struct task_struct *p, struct siginfo *info,int sig, const struct cred *cred);
#else
	int (*task_kill) (struct task_struct * p, struct siginfo * info,int sig, u32 secid);
#endif
	int (*ptrace_access_check)(struct task_struct *child, unsigned int mode);
	int (*ptrace_traceme)(struct task_struct *parent);

	int (*file_permission) (struct file * file, int mask);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
	int (*inode_permission) (struct inode * inode, int mask, unsigned flags);
#else
	int (*inode_permission) (struct inode * inode, int mask);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	int (*inode_getattr) (const struct path * path);
#else
	int (*inode_getattr) (struct vfsmount * mnt, struct dentry * dentry);
#endif
	int (*inode_setattr) (struct dentry * dentry, struct iattr * iattr);
	int (*inode_link) (struct dentry * old_dentry, struct inode * dir,
	struct dentry * new_dentry);
	int (*inode_unlink) (struct inode * dir, struct dentry * dentry);
	int (*inode_rename) (struct inode * old_inode, struct dentry * old_dentry, struct inode * new_inode, struct dentry * new_dentry);
	int (*inode_rmdir) (struct inode * dir, struct dentry * dentry);
	int (*inode_create) (struct inode * dir, struct dentry * dentry, int mode);
	int (*inode_mkdir) (struct inode * dir, struct dentry * dentry, int mask);

	struct module *httc_module;
	atomic_t intercept_refcnt;
};

int httcsec_register_hook(struct httcsec_intercept_module *old_hook, struct httcsec_intercept_module *new_hook);
int httcsec_unregister_hook( struct httcsec_intercept_module *old_hook, struct httcsec_intercept_module *new_hook);
struct httcsec_intercept_module *httcsec_get_hook(void);

#endif
