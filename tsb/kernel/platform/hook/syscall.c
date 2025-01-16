#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#include "syscall.h"
#include "../utils/debug.h"
#include "../utils/write_protect.h"
#include "../../include/version.h"


static unsigned long syscall_table = INVALID_DATA_FULL_FF;
module_param(syscall_table, ulong, 0644);
MODULE_PARM_DESC(syscall_table, "ulong syscall_table address");

static DEFINE_SPINLOCK(syscall_hook_lock);
static unsigned long *writable_syscall_table;
static int syscall_flag[NR_syscalls];
unsigned long *backup_syscall_table[NR_syscalls];


static void backup_syscall(void)
{
	int i = 0;
	unsigned long *sys_call;

	sys_call = (unsigned long *)syscall_table;
	for (i = 0; i < NR_syscalls; i++) {
		backup_syscall_table[i] = (unsigned long *)sys_call[i];
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], NR_syscalls:[%d]\n", __func__, NR_syscalls);
	return;
}
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))&&(defined(__x86_64__)))
unsigned int clear_return_cr0(void)
{
    unsigned int cr0 = 0;
    unsigned int ret;
    asm volatile ("movq %%cr0, %%rax": "=a"(cr0));
    ret = cr0;
    cr0 &= 0xfffeffff;
    asm volatile ("movq %%rax, %%cr0"::"a"(cr0));
    return ret;
}

void setback_cr0(unsigned int val)
{
    asm volatile ("movq %%rax, %%cr0": : "a"(val));
}
#endif

static void wirte_syscall_enrty(int num, unsigned long *new_call,
				unsigned long *w_syscall_table,
				unsigned long *sys_call_table)
{
	unsigned int orig_cr0 = 0;
	if (w_syscall_table == sys_call_table) 
	{
		orig_cr0 = set_syscall_memory_writable((unsigned long)sys_call_table + num , 1, orig_cr0);
		w_syscall_table[num] = (unsigned long)new_call;
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter %s, do write protect!\n", __func__);
		orig_cr0 = set_syscall_memory_writable((unsigned long)sys_call_table + num  , 0, orig_cr0);
	} 
	else 
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter %s, no write protect!\n", __func__);
		w_syscall_table[num] = (unsigned long)new_call;
	}
	return;
}

int hook_restore_system_call(int num, unsigned long *new_call,
			     unsigned long **old_call)
{
	int ret = 0;

	spin_lock(&syscall_hook_lock);
	if (syscall_flag[num] == 0) {
		ret = -EINVAL;
		goto out;
	}

	wirte_syscall_enrty(num, *old_call, writable_syscall_table,
			    (unsigned long *)syscall_table);
	syscall_flag[num] = 0;

out:
	spin_unlock(&syscall_hook_lock);
	return ret;
}

EXPORT_SYMBOL(hook_restore_system_call);

int hook_replace_system_call(int num, unsigned long *new_call,
			     unsigned long **old_call)
{
	int ret = 0;

	spin_lock(&syscall_hook_lock);
	if (syscall_flag[num] == 1) {
		ret = -EINVAL;
		goto out;
	}

	*old_call = (unsigned long *)writable_syscall_table[num];
	wirte_syscall_enrty(num, new_call, writable_syscall_table,
			    (unsigned long *)syscall_table);
	syscall_flag[num] = 1;

out:
	spin_unlock(&syscall_hook_lock);
	return ret;
}

EXPORT_SYMBOL(hook_replace_system_call);

static void *get_writable_syscall_table(void *sct_addr)
{

	return sct_addr;
}

int httc_syscall_init(void)
{
	int ret = 0;

	if (syscall_table == INVALID_DATA_FULL_FF || syscall_table == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "[%s]Insmod Argument[%lx] Error!\n",__func__, syscall_table);
		ret = -EINVAL;
		goto out;
	} else {
		DEBUG_MSG(HTTC_TSB_DEBUG,
			  "syscall_table:[%0lx], syscall_table:[%p], NR_syscalls:[%d]!\n",
			  syscall_table, (unsigned long *)syscall_table, NR_syscalls);
	}

#if defined(CONFIG_ARM64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = lookup_init_mm();
	if(ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "lookup_init_mm error!\n");
		ret = -EINVAL;
		goto out;
	}
#endif

	backup_syscall();

	writable_syscall_table =
	    get_writable_syscall_table((void *)syscall_table);
	if (!writable_syscall_table) {
		ret = -EINVAL;
		goto out;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "writable syscall address:[%p], syscall_table:[%p]\n",
		  writable_syscall_table, (unsigned long *)syscall_table);

out:
	return ret;
}

void httc_syscall_exit(void)
{
	if (writable_syscall_table
	    && writable_syscall_table != (unsigned long *)syscall_table)
		vunmap((const void *)((unsigned long)writable_syscall_table &
				      PAGE_MASK));
	return;
}
