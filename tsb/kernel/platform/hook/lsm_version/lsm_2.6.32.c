#include <linux/security.h>
#include <linux/types.h>
#include <linux/module.h>


#include "../../../include/version.h"
#include "../hook.h"
#include "../syscall.h"
//#include "../lsm.h"
//#include "../../intercept/intercept.h"
//#include "../../intercept/intercept_module.h"
#include "engine_func.h"
#include "../../utils/debug.h"

static unsigned long hook_security_address = INVALID_DATA_FULL_FF;
static unsigned long mountlock = INVALID_DATA_FULL_FF;
module_param(hook_security_address, ulong, 0644);
MODULE_PARM_DESC(hook_security_address, "ulong security_security_hook address");
module_param(mountlock, ulong, 0644);
MODULE_PARM_DESC(mountlock, "ulong mount lock address");

//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 4))
//seqlock_t *pmount_lock;
//#else
//struct lglock *pmount_lock = 0;
//#endif

static struct security_operations *lsm_old_ops;
static struct security_operations **pp_security_ops;
static struct security_operations lsm_httc_ops;



static int lsm_httc_bprm_check_security(struct linux_binprm *bprm)
{
	CALL_INTERCEPT_FUNC(bprm_check_security,bprm);
}

static int lsm_httc_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot, 
	unsigned long flags, unsigned long addr, unsigned long addr_only)
{
	CALL_INTERCEPT_FUNC(file_mmap, file, reqprot, prot, flags, addr, addr_only);
}

//static int lsm_httc_kernel_module_from_file(struct file *file)
//{
//	CALL_INTERCEPT_FUNC(kernel_module_from_file, file);
//}

static int lsm_httc_dentry_open(struct file *file, const struct cred *cred)
{
	CALL_INTERCEPT_FUNC(dentry_open, file, cred);
	return 0;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
static int lsm_httc_inode_permission(struct inode *inode, int mask, unsigned flags)
{
	CALL_INTERCEPT_FUNC(inode_permission, inode, mask, flags);
}
#else
static int lsm_httc_inode_permission(struct inode *inode, int mask)
{
	CALL_INTERCEPT_FUNC(inode_permission, inode, mask);
}
#endif

static int lsm_httc_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	CALL_INTERCEPT_FUNC(inode_getattr, mnt, dentry);
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

static int lsm_httc_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
	CALL_INTERCEPT_FUNC(inode_create, dir, dentry, mode);
}

static int lsm_httc_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	CALL_INTERCEPT_FUNC(inode_rmdir, dir, dentry);
}

static int lsm_httc_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	CALL_INTERCEPT_FUNC(inode_mkdir, dir, dentry, mode);
}

static int lsm_httc_init_module(void __user * umod, unsigned long len, const char __user * uargs)
{
	CALL_SYSENGINE_FUNC(init_module, umod, len, uargs);
}

asmlinkage int (*original_init_module) (void __user * umod, unsigned long len, const char __user * uargs);
asmlinkage int httc_init_module(void __user * umod, unsigned long len, const char __user * uargs)
{
	int ret;

	atomic_inc(&platform_refcnt);
	if (!lsm_httc_init_module(umod, len, uargs))
		ret = original_init_module(umod, len, uargs);
	else
		ret = -EPERM;
	atomic_dec(&platform_refcnt);

	return ret;
}

static void lsm_init_prepare(void)
{

	memcpy(&lsm_httc_ops, lsm_old_ops, sizeof(lsm_httc_ops));
	strcpy(lsm_httc_ops.name, "httc_tsb");

	lsm_httc_ops.bprm_check_security = lsm_httc_bprm_check_security;
	lsm_httc_ops.file_mmap = lsm_httc_file_mmap;
	//lsm_httc_ops.kernel_module_from_file = lsm_httc_kernel_module_from_file;
	lsm_httc_ops.dentry_open = lsm_httc_dentry_open;
	lsm_httc_ops.task_kill = lsm_httc_task_kill;

	lsm_httc_ops.ptrace_access_check = lsm_httc_ptrace_access_check;
	lsm_httc_ops.ptrace_traceme = lsm_httc_ptrace_traceme;

	lsm_httc_ops.file_permission = lsm_httc_file_permission;
	lsm_httc_ops.inode_permission = lsm_httc_inode_permission;
	lsm_httc_ops.inode_setattr = lsm_httc_inode_setattr;
	lsm_httc_ops.inode_getattr = lsm_httc_inode_getattr;
	lsm_httc_ops.inode_link = lsm_httc_inode_link;
	lsm_httc_ops.inode_unlink = lsm_httc_inode_unlink;
	lsm_httc_ops.inode_rename = lsm_httc_inode_rename;
	lsm_httc_ops.inode_create = lsm_httc_inode_create;
	lsm_httc_ops.inode_mkdir = lsm_httc_inode_mkdir;
	lsm_httc_ops.inode_rmdir = lsm_httc_inode_rmdir;
}

int lsm_init(void)
{
	int r = 0;

	if ((hook_security_address == INVALID_DATA_FULL_FF
		|| hook_security_address == 0)
		|| (mountlock == INVALID_DATA_FULL_FF/* || mountlock == 0*/)) {
			DEBUG_MSG(HTTC_TSB_INFO, "Insmod Argument Error!\n");
			return -EINVAL;
	}
	pp_security_ops = (struct security_operations **)hook_security_address;
	lsm_old_ops = *pp_security_ops;

//#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 4))
//	pmount_lock = (seqlock_t *) mountlock;
//#else
//	pmount_lock = (struct lglock *)mountlock;
//#endif

	//find some address
	//if (hook_search_ksym("security_ops", (unsigned long *) &pp_security_ops))
	//{
	//	printk(KERN_ERR "security_ops not found\n");
	//	r = -1;
	//	goto out;
	//}

	//pr_dev("pp_security_ops at  %p\n", pp_security_ops);
	//lsm_old_ops = *pp_security_ops;
	//pr_dev("lsm_old_ops at  %p\n", lsm_old_ops);

//creare our lsm_ops;
	lsm_init_prepare();
	pr_dev("lsm_httc_ops at  %p\n", &lsm_httc_ops);

	hook_replace_pointer((void **)pp_security_ops,&lsm_httc_ops);

	hook_replace_system_call(__NR_init_module, (unsigned long *)httc_init_module, (unsigned long **)&original_init_module);

	pr_dev("new security_ops at  %p\n", *pp_security_ops);

//out:
	return r;
}
void lsm_exit(void)
{
	hook_restore_system_call(__NR_init_module, (unsigned long *)httc_init_module, (unsigned long **)&original_init_module);

	if (lsm_old_ops)
	{
		hook_replace_pointer((void **)pp_security_ops,lsm_old_ops);
		//*pp_security_ops = lsm_old_ops;
	}
}
