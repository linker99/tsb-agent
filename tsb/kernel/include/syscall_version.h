#ifndef __SYSCALL_VERSION_H__
#define __SYSCALL_VERSION_H__

#if defined(CONFIG_SW)
#include <asm-generic/unistd.h>
#else
#include <linux/unistd.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/syscall.h>
#endif
#endif

#ifndef NR_syscalls
#define NR_syscalls __NR_syscalls
#endif

#endif // __SYSCALL_VERSION_H__
