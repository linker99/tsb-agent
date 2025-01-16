#ifndef __WRITE_PROTECT_H__
#define __WRITE_PROTECT_H__

#include <linux/module.h>

static void inline set_kernel_writable(void)
{
#if defined(__x86_64__)
	write_cr0(read_cr0() & ~X86_CR0_WP);
#endif
}

static void inline set_kernel_readonly(void)
{
#if defined(__x86_64__)
	write_cr0(read_cr0() | X86_CR0_WP);
#endif
}

unsigned int set_kernel_wp(int writable, unsigned int val);

int set_memory_page_wp(unsigned long addr, int writable);

//int set_syscall_memory_page_wp(unsigned long addr, int writable);

#if defined(__x86_64__)
#define set_memory_writable(addr, writable, val)	\
	set_kernel_wp(writable, val)
#elif defined(CONFIG_ARM64)
#define set_memory_writable(addr, writable, val)	\
	set_memory_page_wp(addr, writable)
#else
#define set_memory_writable(addr, writable, val)	\
	set_kernel_wp(writable, val)
#endif

#if defined(__x86_64__)
#define set_syscall_memory_writable(addr, writable, val)	\
	set_kernel_wp(writable, val)
#elif defined(CONFIG_ARM64)
#define set_syscall_memory_writable(addr, writable, val)	\
		set_memory_page_wp(addr, writable)
#else
#define set_syscall_memory_writable(addr, writable, val)	\
	set_kernel_wp(writable, val)
#endif
int lookup_init_mm(void);

#endif	/* __WRITE_PROTECT_H__ */
