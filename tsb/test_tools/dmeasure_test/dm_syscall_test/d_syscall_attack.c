//#include <asm/desc.h>
#include <linux/fdtable.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/sched.h>
//#include <asm/uaccess.h>
#include <linux/utsname.h>
#include "support.h"

#define SYSCALL	"SysCallTable"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <asm/unistd.h>
#endif


static asmlinkage long (*old_sys_getpid)(void) = 0;
static asmlinkage long new_sys_getpid(void)
{
        printk("Enter syscall item '%s'\n", __func__);
        return old_sys_getpid();
}


static asmlinkage long (*old_sys_uname)(struct old_utsname __user *arg);
static asmlinkage long new_sys_uname(struct old_utsname __user *arg)
{
        printk("Enter syscall item '%s'\n", __func__);
        return old_sys_uname((struct old_utsname __user *)arg);
}

static asmlinkage long (*old_sys_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
static asmlinkage long new_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	printk("Enter syscall item '%s'\n", __func__);
	return old_sys_reboot(magic1, magic2, cmd, arg);
}

int dmeasure_test_modify_sycall_init(void)
{
        int ret = 0;

        //hook_replace_system_call(__NR_getpid, (unsigned long *)new_sys_getpid, (unsigned long **)&old_sys_getpid);
        //hook_replace_system_call(__NR_uname, (unsigned long *)new_sys_uname, (unsigned long **)&old_sys_uname);
		hook_replace_system_call(__NR_reboot, (unsigned long *)new_sys_reboot, (unsigned long **)&old_sys_reboot);

        return ret;
}
int dmeasure_test_modify_sycall_exit(void)
{
        int ret = 0;

        //hook_restore_system_call(__NR_getpid, (unsigned long *)new_sys_getpid, (unsigned long **)&old_sys_getpid);
        //hook_restore_system_call(__NR_uname, (unsigned long *)new_sys_uname, (unsigned long **)&old_sys_uname);
		hook_restore_system_call(__NR_reboot, (unsigned long *)new_sys_reboot, (unsigned long **)&old_sys_reboot);

        return ret;
}
