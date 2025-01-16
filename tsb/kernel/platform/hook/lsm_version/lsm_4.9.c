#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <linux/rwlock.h>
#include <linux/file.h>
#include <linux/unistd.h>

#if defined(__aarch64__)
//#include <asm/unistd32.h>
#endif

#include "../../../include/version.h"
#include "../hook.h"
#include "engine_func.h"
#include "../../utils/debug.h"
#include "../../utils/write_protect.h"


static unsigned long hook_security_address = INVALID_DATA_FULL_FF;
static unsigned long mountlock = INVALID_DATA_FULL_FF;
module_param(hook_security_address, ulong, 0644);
MODULE_PARM_DESC(hook_security_address, "ulong security_hook_heads address");
module_param(mountlock, ulong, 0644);
MODULE_PARM_DESC(mountlock, "ulong mount lock address");

seqlock_t *pmount_lock;

#define MAX_HOOKS 64
static int hook_number;
struct security_hook_list httcsec_hooks[MAX_HOOKS];
static struct security_hook_heads *p_security_hook_heads = NULL;


#include "engine_func.h"


static int lsm_httc_bprm_check_security(struct linux_binprm *bprm)
{
	CALL_INTERCEPT_FUNC(bprm_check_security,bprm);
}

static int lsm_httc_mmap_file(struct file *file, unsigned long reqprot,
	unsigned long prot, unsigned long flags)
{
	CALL_INTERCEPT_FUNC(mmap_file, file, reqprot, prot, flags);
}

static int lsm_httc_kernel_read_file(struct file *file, enum kernel_read_file_id id)
{
	CALL_INTERCEPT_FUNC(kernel_read_file, file, id);
}

static int lsm_httc_file_open(struct file *file, const struct cred *cred)
{
	CALL_INTERCEPT_FUNC(file_open, file, cred);
}

static int lsm_httc_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
{
	CALL_INTERCEPT_FUNC(task_kill, p, info, sig, secid);
}

static int lsm_httc_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
	CALL_INTERCEPT_FUNC(ptrace_access_check, child, mode);
}

static int lsm_httc_ptrace_traceme(struct task_struct *parent)
{
	CALL_INTERCEPT_FUNC(ptrace_traceme, parent);
}

/* check file permit */
static int lsm_httc_file_permission(struct file *file, int mask)
{
	CALL_INTERCEPT_FUNC(file_permission, file, mask);
}

static int lsm_httc_inode_permission(struct inode *inode, int mask)
{
	CALL_INTERCEPT_FUNC(inode_permission, inode, mask);
}

static int lsm_httc_inode_getattr(const struct path *path)
{
	CALL_INTERCEPT_FUNC(inode_getattr, path);
}

static int lsm_httc_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	CALL_INTERCEPT_FUNC(inode_setattr, dentry, iattr);
}

static int lsm_httc_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	CALL_INTERCEPT_FUNC(inode_link, old_dentry, dir, new_dentry);
}

static int lsm_httc_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	CALL_INTERCEPT_FUNC(inode_unlink, dir, dentry);
}

static int lsm_httc_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry)
{
	CALL_INTERCEPT_FUNC(inode_rename, old_inode, old_dentry, new_inode, new_dentry);
}

static int lsm_httc_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	CALL_INTERCEPT_FUNC(inode_create, dir, dentry, mode);
}

static int lsm_httc_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	CALL_INTERCEPT_FUNC(inode_rmdir, dir, dentry);
}

static int lsm_httc_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	CALL_INTERCEPT_FUNC(inode_mkdir, dir, dentry, mask);
}

static int lsm_httc_init_module(void __user * umod, unsigned long len, const char __user * uargs)
{
	CALL_SYSENGINE_FUNC(init_module, umod, len, uargs);
}

asmlinkage int (*original_init_module) (void __user * umod, unsigned long len, const char __user * uargs);
asmlinkage int httc_init_module(void __user * umod, unsigned long len, const char __user * uargs)
{
	int ret = 0;

	atomic_inc(&platform_refcnt);
	if (!lsm_httc_init_module(umod, len, uargs))
		ret = original_init_module(umod, len, uargs);
	else
		ret = -EPERM;
	atomic_dec(&platform_refcnt);

	return ret;
}

#define HTTCSEC_LSM_HOOK_INIT(HEAD, HOOK)                               \
        httcsec_hooks[hook_number].head = &p_security_hook_heads->HEAD; \
        httcsec_hooks[hook_number].hook.HEAD = HOOK;                    \
        hook_number++;

static void init_hooks(void)
{
	/* check executable program permit */
	HTTCSEC_LSM_HOOK_INIT(bprm_check_security,
			      lsm_httc_bprm_check_security);
	HTTCSEC_LSM_HOOK_INIT(mmap_file, lsm_httc_mmap_file);
	HTTCSEC_LSM_HOOK_INIT(kernel_read_file, lsm_httc_kernel_read_file);
	HTTCSEC_LSM_HOOK_INIT(file_open, lsm_httc_file_open);
	HTTCSEC_LSM_HOOK_INIT(task_kill, lsm_httc_task_kill);

	HTTCSEC_LSM_HOOK_INIT(ptrace_access_check, lsm_httc_ptrace_access_check);
	HTTCSEC_LSM_HOOK_INIT(ptrace_traceme, lsm_httc_ptrace_traceme);

	/* check file permit */
	HTTCSEC_LSM_HOOK_INIT(file_permission, lsm_httc_file_permission);
	HTTCSEC_LSM_HOOK_INIT(inode_permission, lsm_httc_inode_permission);
	HTTCSEC_LSM_HOOK_INIT(inode_getattr, lsm_httc_inode_getattr);
	HTTCSEC_LSM_HOOK_INIT(inode_setattr, lsm_httc_inode_setattr);
	HTTCSEC_LSM_HOOK_INIT(inode_link, lsm_httc_inode_link);
	HTTCSEC_LSM_HOOK_INIT(inode_unlink, lsm_httc_inode_unlink);
	HTTCSEC_LSM_HOOK_INIT(inode_rename, lsm_httc_inode_rename);
	HTTCSEC_LSM_HOOK_INIT(inode_create, lsm_httc_inode_create);
	HTTCSEC_LSM_HOOK_INIT(inode_rmdir, lsm_httc_inode_rmdir);
	HTTCSEC_LSM_HOOK_INIT(inode_mkdir, lsm_httc_inode_mkdir);
}

void httc_security_add_hooks(struct security_hook_list *hooks, int count,
			     char *lsm)
{
	int i;

	for (i = 0; i < count; i++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
		hooks[i].lsm = lsm;
#endif
		list_add_tail_rcu(&hooks[i].list, hooks[i].head);
	}

}

#ifndef CONFIG_SECURITY_SELINUX_DISABLE
static inline void security_delete_hooks(struct security_hook_list *hooks,
					 int count)
{
	int i;

	for (i = 0; i < count; i++)
		list_del_rcu(&hooks[i].list);
}
#endif

int lsm_init(void)
{
	int ret = 0;

	if ((hook_security_address == INVALID_DATA_FULL_FF ||
	     hook_security_address == 0) ||
	    (mountlock == INVALID_DATA_FULL_FF ||
	     mountlock == 0)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod Argument Error!\n");
		return -EINVAL;
	}
	//if (hook_search_ksym("security_hook_heads", (unsigned long *) &hook_security_address))
	//{
	//	printk(KERN_ERR "security_hook_heads not found\n");
	//	ret = -1;
	//	goto out;
	//}
	//if (hook_search_ksym("mount_lock", (unsigned long *) &mountlock))
	//{
	//	printk(KERN_ERR "mount_lock not found\n");
	//	ret = -1;
	//	goto out;
	//}

	p_security_hook_heads = (struct security_hook_heads *)hook_security_address;

	pmount_lock = (seqlock_t *) mountlock;

	init_hooks();

	//set_memory_writable(hook_security_address, 1);
	httc_security_add_hooks(httcsec_hooks, hook_number, "httcsec");
	//set_memory_writable(hook_security_address, 0);

	DEBUG_MSG(HTTC_TSB_DEBUG, "LSM Init OK! Hook Head Addr:[%p]\n",
                 p_security_hook_heads);
	hook_replace_system_call(__NR_init_module, (unsigned long *)httc_init_module, (unsigned long **)&original_init_module);

//out:
	return ret;
}

void lsm_exit(void)
{

	hook_restore_system_call(__NR_init_module, (unsigned long *)httc_init_module, (unsigned long **)&original_init_module);

	//set_memory_writable(hook_security_address, 1);
	security_delete_hooks(httcsec_hooks, hook_number);
	//set_memory_writable(hook_security_address, 0);
	DEBUG_MSG(HTTC_TSB_DEBUG, "LSM Exit OK!\n");
	return;
}
