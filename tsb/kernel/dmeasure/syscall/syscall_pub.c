#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include "dmeasure_types.h"
#include "syscall_version.h"
/* #include "memory_protection.h" */
#include "version.h"
//#include "policy/policy_dmeasure.h"
//#include "policy/list_dmeasure_trigger.h"
///* #include "sec_domain.h" */
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
//#include "tpcmif.h"
#include "../utils/traceability.h"
#include "sec_domain.h"
#include "function_types.h"
#include "tpcm/tpcmif.h"
#include "log/log.h"
#include "../policy/policy_dmeasure.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "utils/debug.h"

#define SYSCALL_NAME_LEN		32

static unsigned long syscall_table = INVALID_DATA_FULL_FF;
module_param(syscall_table, ulong, 0644);
MODULE_PARM_DESC(syscall_table, "ulong syscall_table address");

struct syscall_measure {
	unsigned long *syscall_addr;
	unsigned long *backup_syscall_table[NR_syscalls];
	int len_base;
	unsigned char hash[LEN_HASH];
	//char base[0];
};

struct syscall_measure *sys_m = NULL;

/* #define ACTION_NAME	"SysCallTable" */
//#define CIRCLE_NAME   "Periodicity"
#define ACTION_NAME	DM_ACTION_SYSCALLTABLE_NAME

//static struct dmeasure_feature_conf *dmeasure_feature = NULL;

static void get_syscall_name(int numb, char *name)
{
	memset(name, 0, SYSCALL_NAME_LEN);
	switch (numb) {
	case __NR_read:
		strcpy(name, "__NR_read");
		break;
	case __NR_write:
		strcpy(name, "__NR_write");
		break;
	case __NR_close:
		strcpy(name, "__NR_close");
		break;
	case __NR_fstat:
		strcpy(name, "__NR_fstat");
		break;
	case __NR_lseek:
		strcpy(name, "__NR_lseek");
		break;
	case __NR_mmap:
		strcpy(name, "__NR_mmap");
		break;
	case __NR_mprotect:
		strcpy(name, "__NR_mprotect");
		break;
	case __NR_munmap:
		strcpy(name, "__NR_munmap");
		break;
	case __NR_brk:
		strcpy(name, "__NR_brk");
		break;
	case __NR_rt_sigaction:
		strcpy(name, "__NR_rt_sigaction");
		break;
	case __NR_rt_sigprocmask:
		strcpy(name, "__NR_rt_sigprocmask");
		break;
	case __NR_rt_sigreturn:
		strcpy(name, "__NR_rt_sigreturn");
		break;
	case __NR_ioctl:
		strcpy(name, "__NR_ioctl");
		break;
	case __NR_pread64:
		strcpy(name, "__NR_pread64");
		break;
	case __NR_pwrite64:
		strcpy(name, "__NR_pwrite64");
		break;
	case __NR_readv:
		strcpy(name, "__NR_readv");
		break;
	case __NR_writev:
		strcpy(name, "__NR_writev");
		break;
	case __NR_sched_yield:
		strcpy(name, "__NR_sched_yield");
		break;
	case __NR_mremap:
		strcpy(name, "__NR_mremap");
		break;
	case __NR_msync:
		strcpy(name, "__NR_msync");
		break;
	case __NR_mincore:
		strcpy(name, "__NR_mincore");
		break;
	case __NR_madvise:
		strcpy(name, "__NR_madvise");
		break;
#ifndef CONFIG_CSKY
	case __NR_shmget:
		strcpy(name, "__NR_shmget");
		break;
	case __NR_shmat:
		strcpy(name, "__NR_shmat");
		break;
	case __NR_shmctl:
		strcpy(name, "__NR_shmctl");
		break;
#endif
	case __NR_dup:
		strcpy(name, "__NR_dup");
		break;
	case __NR_nanosleep:
		strcpy(name, "__NR_nanosleep");
		break;
	case __NR_getitimer:
		strcpy(name, "__NR_getitimer");
		break;
	case __NR_setitimer:
		strcpy(name, "__NR_setitimer");
		break;
	case __NR_getpid:
		strcpy(name, "__NR_getpid");
		break;
	case __NR_sendfile:
		strcpy(name, "__NR_sendfile");
		break;
#ifndef CONFIG_CSKY
	case __NR_socket:
		strcpy(name, "__NR_socket");
		break;
	case __NR_connect:
		strcpy(name, "__NR_connect");
		break;
	case __NR_accept:
		strcpy(name, "__NR_accept");
		break;
	case __NR_sendto:
		strcpy(name, "__NR_sendto");
		break;
	case __NR_recvfrom:
		strcpy(name, "__NR_recvfrom");
		break;
	case __NR_sendmsg:
		strcpy(name, "__NR_sendmsg");
		break;
	case __NR_recvmsg:
		strcpy(name, "__NR_recvmsg");
		break;
	case __NR_shutdown:
		strcpy(name, "__NR_shutdown");
		break;
	case __NR_bind:
		strcpy(name, "__NR_bind");
		break;
	case __NR_listen:
		strcpy(name, "__NR_listen");
		break;
	case __NR_getsockname:
		strcpy(name, "__NR_getsockname");
		break;
	case __NR_getpeername:
		strcpy(name, "__NR_getpeername");
		break;
	case __NR_socketpair:
		strcpy(name, "__NR_socketpair");
		break;
	case __NR_setsockopt:
		strcpy(name, "__NR_setsockopt");
		break;
	case __NR_getsockopt:
		strcpy(name, "__NR_getsockopt");
		break;
#endif
	case __NR_clone:
		strcpy(name, "__NR_clone");
		break;
	case __NR_execve:
		strcpy(name, "__NR_execve");
		break;
	case __NR_exit:
		strcpy(name, "__NR_exit");
		break;
	case __NR_wait4:
		strcpy(name, "__NR_wait4");
		break;
	case __NR_kill:
		strcpy(name, "__NR_kill");
		break;
	case __NR_uname:
		strcpy(name, "__NR_uname");
		break;
#ifndef CONFIG_CSKY
	case __NR_semget:
		strcpy(name, "__NR_semget");
		break;
	case __NR_semop:
		strcpy(name, "__NR_semop");
		break;
	case __NR_semctl:
		strcpy(name, "__NR_semctl");
		break;
	case __NR_shmdt:
		strcpy(name, "__NR_shmdt");
		break;
	case __NR_msgget:
		strcpy(name, "__NR_msgget");
		break;
	case __NR_msgsnd:
		strcpy(name, "__NR_msgsnd");
		break;
	case __NR_msgrcv:
		strcpy(name, "__NR_msgrcv");
		break;
	case __NR_msgctl:
		strcpy(name, "__NR_msgctl");
		break;
#endif
	case __NR_fcntl:
		strcpy(name, "__NR_fcntl");
		break;
	case __NR_flock:
		strcpy(name, "__NR_flock");
		break;
	case __NR_fsync:
		strcpy(name, "__NR_fsync");
		break;
	case __NR_fdatasync:
		strcpy(name, "__NR_fdatasync");
		break;
	case __NR_truncate:
		strcpy(name, "__NR_truncate");
		break;
	case __NR_ftruncate:
		strcpy(name, "__NR_ftruncate");
		break;
	case __NR_getcwd:
		strcpy(name, "__NR_getcwd");
		break;
	case __NR_chdir:
		strcpy(name, "__NR_chdir");
		break;
	case __NR_fchdir:
		strcpy(name, "__NR_fchdir");
		break;
	case __NR_fchmod:
		strcpy(name, "__NR_fchmod");
		break;
	case __NR_fchown:
		strcpy(name, "__NR_fchown");
		break;
	case __NR_umask:
		strcpy(name, "__NR_umask");
		break;
	case __NR_gettimeofday:
		strcpy(name, "__NR_gettimeofday");
		break;
	case __NR_getrlimit:
		strcpy(name, "__NR_getrlimit");
		break;
	case __NR_getrusage:
		strcpy(name, "__NR_getrusage");
		break;
	case __NR_sysinfo:
		strcpy(name, "__NR_sysinfo");
		break;
	case __NR_times:
		strcpy(name, "__NR_times");
		break;
	case __NR_ptrace:
		strcpy(name, "__NR_ptrace");
		break;
	case __NR_getuid:
		strcpy(name, "__NR_getuid");
		break;
	case __NR_syslog:
		strcpy(name, "__NR_syslog");
		break;
	case __NR_getgid:
		strcpy(name, "__NR_getgid");
		break;
	case __NR_getegid:
		strcpy(name, "__NR_getegid");
		break;
	case __NR_setuid:
		strcpy(name, "__NR_setuid");
		break;
	case __NR_setgid:
		strcpy(name, "__NR_setgid");
		break;
	case __NR_geteuid:
		strcpy(name, "__NR_geteuid");
		break;
	case __NR_setpgid:
		strcpy(name, "__NR_setpgid");
		break;
	case __NR_getppid:
		strcpy(name, "__NR_getppid");
		break;
	case __NR_setsid:
		strcpy(name, "__NR_setsid");
		break;
	case __NR_setreuid:
		strcpy(name, "__NR_setreuid");
		break;
	case __NR_setregid:
		strcpy(name, "__NR_setregid");
		break;
	case __NR_getgroups:
		strcpy(name, "__NR_getgroups");
		break;
	case __NR_setgroups:
		strcpy(name, "__NR_setgroups");
		break;
	case __NR_setresuid:
		strcpy(name, "__NR_setresuid");
		break;
	case __NR_getresuid:
		strcpy(name, "__NR_getresuid");
		break;
	case __NR_setresgid:
		strcpy(name, "__NR_setresgid");
		break;
	case __NR_getresgid:
		strcpy(name, "__NR_getresgid");
		break;
	case __NR_getpgid:
		strcpy(name, "__NR_getpgid");
		break;
	case __NR_setfsuid:
		strcpy(name, "__NR_setfsuid");
		break;
	case __NR_setfsgid:
		strcpy(name, "__NR_setfsgid");
		break;
	case __NR_getsid:
		strcpy(name, "__NR_getsid");
		break;
	case __NR_capget:
		strcpy(name, "__NR_capget");
		break;
	case __NR_capset:
		strcpy(name, "__NR_capset");
		break;
	case __NR_rt_sigpending:
		strcpy(name, "__NR_rt_sigpending");
		break;
	case __NR_rt_sigtimedwait:
		strcpy(name, "__NR_rt_sigtimedwait");
		break;
	case __NR_rt_sigqueueinfo:
		strcpy(name, "__NR_rt_sigqueueinfo");
		break;
	case __NR_rt_sigsuspend:
		strcpy(name, "__NR_sigsuspend");
		break;
	case __NR_sigaltstack:
		strcpy(name, "__NR_sigaltstack");
		break;
	case __NR_personality:
		strcpy(name, "__NR_personality");
		break;
	case __NR_statfs:
		strcpy(name, "__NR_statfs");
		break;
	case __NR_fstatfs:
		strcpy(name, "__NR_fstatfs");
		break;
	case __NR_getpriority:
		strcpy(name, "__NR_getpriority");
		break;
	case __NR_setpriority:
		strcpy(name, "__NR_setpriority");
		break;
	case __NR_sched_setparam:
		strcpy(name, "__NR_sched_setparam");
		break;
	case __NR_sched_getparam:
		strcpy(name, "__NR_sched_getparam");
		break;
	case __NR_sched_setscheduler:
		strcpy(name, "__NR_sched_setscheduler");
		break;
	case __NR_sched_getscheduler:
		strcpy(name, "__NR_sched_getscheduler");
		break;
	case __NR_sched_get_priority_max:
		strcpy(name, "__NR_sched_geet_priority_max");
		break;
	case __NR_sched_get_priority_min:
		strcpy(name, "__NR_sched_get_priority_min");
		break;
	case __NR_sched_rr_get_interval:
		strcpy(name, "__NR_sched_rr_get_interval");
		break;
	case __NR_mlock:
		strcpy(name, "__NR_mlock");
		break;
	case __NR_munlock:
		strcpy(name, "__NR_munlock");
		break;
	case __NR_mlockall:
		strcpy(name, "__NR_mlockall");
		break;
	case __NR_munlockall:
		strcpy(name, "__NR_munlockall");
		break;
	case __NR_vhangup:
		strcpy(name, "__NR_uhangup");
		break;
	case __NR_pivot_root:
		strcpy(name, "__NR_pivot_root");
		break;
	case __NR_prctl:
		strcpy(name, "__NR_prctl");
		break;
	case __NR_adjtimex:
		strcpy(name, "__NR_adjtimex");
		break;
	case __NR_setrlimit:
		strcpy(name, "__NR_setrlimit");
		break;
	case __NR_chroot:
		strcpy(name, "__NR_chroot");
		break;
	case __NR_sync:
		strcpy(name, "__NR_sync");
		break;
	case __NR_acct:
		strcpy(name, "__NR_acct");
		break;
	case __NR_settimeofday:
		strcpy(name, "__NR_settimeofday");
		break;
	case __NR_mount:
		strcpy(name, "__NR_mount");
		break;
	case __NR_umount2:
		strcpy(name, "__NR_umount2");
		break;
	case __NR_swapon:
		strcpy(name, "__NR_swapon");
		break;
	case __NR_swapoff:
		strcpy(name, "__NR_swapoff");
		break;
	case __NR_reboot:
		strcpy(name, "__NR_reboot");
		break;
	case __NR_sethostname:
		strcpy(name, "__NR_sethostname");
		break;
	case __NR_setdomainname:
		strcpy(name, "__NR_setdomainname");
		break;
	case __NR_init_module:
		strcpy(name, "__NR_init_module");
		break;
	case __NR_delete_module:
		strcpy(name, "__NR_delete_module");
		break;
	case __NR_quotactl:
		strcpy(name, "__NR_quotactl");
		break;
	case __NR_nfsservctl:
		strcpy(name, "__NR_nfsservctl");
		break;
	case __NR_gettid:
		strcpy(name, "__NR_gettid");
		break;
	case __NR_readahead:
		strcpy(name, "__NR_readahead");
		break;
	case __NR_setxattr:
		strcpy(name, "__NR_setxattr");
		break;
	case __NR_lsetxattr:
		strcpy(name, "__NR_lsetxattr");
		break;
	case __NR_fsetxattr:
		strcpy(name, "__NR_fsetxattr");
		break;
	case __NR_getxattr:
		strcpy(name, "__NR_getxattr");
		break;
	case __NR_lgetxattr:
		strcpy(name, "__NR_lgetxattr");
		break;
	case __NR_fgetxattr:
		strcpy(name, "__NR_fgetxattr");
		break;
	case __NR_listxattr:
		strcpy(name, "__NR_listxattr");
		break;
	case __NR_llistxattr:
		strcpy(name, "__NR_llistxattr");
		break;
	case __NR_flistxattr:
		strcpy(name, "__NR_flistxattr");
		break;
	case __NR_removexattr:
		strcpy(name, "__NR_removexattr");
		break;
	case __NR_lremovexattr:
		strcpy(name, "__NR_lremovexattr");
		break;
	case __NR_fremovexattr:
		strcpy(name, "__NR_fremovexattr");
		break;
	case __NR_tkill:
		strcpy(name, "__NR_tkill");
		break;
	case __NR_futex:
		strcpy(name, "__NR_futex");
		break;
	case __NR_sched_setaffinity:
		strcpy(name, "__NR_setaffinity");
		break;
	case __NR_sched_getaffinity:
		strcpy(name, "__NR_sched_getaffinity");
		break;
	case __NR_io_setup:
		strcpy(name, "__NR_io_setup");
		break;
	case __NR_io_destroy:
		strcpy(name, "__NR_io_destroy");
		break;
	case __NR_io_getevents:
		strcpy(name, "__NR_io_getevents");
		break;
	case __NR_io_submit:
		strcpy(name, "__NR_io_submit");
		break;
	case __NR_io_cancel:
		strcpy(name, "__NR_io_cancel");
		break;
	case __NR_lookup_dcookie:
		strcpy(name, "__NR_lookup_dcookie");
		break;
	case __NR_remap_file_pages:
		strcpy(name, "__NR_remap_file_pages");
		break;
	case __NR_getdents64:
		strcpy(name, "__NR_getdents64");
		break;
	case __NR_set_tid_address:
		strcpy(name, "__NR_set_tid_address");
		break;
	case __NR_restart_syscall:
		strcpy(name, "__NR_restart_syscall");
		break;
#ifndef CONFIG_CSKY
	case __NR_semtimedop:
		strcpy(name, "__NR_semtimedop");
		break;
#endif
#ifndef CONFIG_ARM
	case __NR_fadvise64:
		strcpy(name, "__NR_fadvise64");
		break;
#endif
	case __NR_timer_create:
		strcpy(name, "__NR_timer_create");
		break;
	case __NR_timer_settime:
		strcpy(name, "__NR_timer_settime");
		break;
	case __NR_timer_gettime:
		strcpy(name, "__NR_timer_gettime");
		break;
	case __NR_timer_getoverrun:
		strcpy(name, "__NR_timer_getoverrun");
		break;
	case __NR_timer_delete:
		strcpy(name, "__NR_timer_delete");
		break;
	case __NR_clock_settime:
		strcpy(name, "__NR_clock_settime");
		break;
	case __NR_clock_gettime:
		strcpy(name, "__NR_clock_gettime");
		break;
	case __NR_clock_getres:
		strcpy(name, "__NR_clock_getres");
		break;
	case __NR_clock_nanosleep:
		strcpy(name, "__NR_clock_nanosleep");
		break;
	case __NR_exit_group:
		strcpy(name, "__NR_exit_group");
		break;
	case __NR_epoll_ctl:
		strcpy(name, "__NR_epoll_ctl");
		break;
	case __NR_tgkill:
		strcpy(name, "__NR_tgkill");
		break;
	case __NR_mbind:
		strcpy(name, "__NR_mbind");
		break;
	case __NR_set_mempolicy:
		strcpy(name, "__NR_set_mempolicy");
		break;
	case __NR_get_mempolicy:
		strcpy(name, "__NR_get_mempolicy");
		break;
	case __NR_mq_open:
		strcpy(name, "__NR_mq_open");
		break;
	case __NR_mq_unlink:
		strcpy(name, "__NR_mq_unlink");
		break;
	case __NR_mq_timedsend:
		strcpy(name, "__NR_mq_timedsend");
		break;
	case __NR_mq_timedreceive:
		strcpy(name, "__NR_mq_timedreceive");
		break;
	case __NR_mq_notify:
		strcpy(name, "__NR_mq_notify");
		break;
	case __NR_mq_getsetattr:
		strcpy(name, "__NR_mq_getsetattr");
		break;
	case __NR_kexec_load:
		strcpy(name, "__NR_kexec_load");
		break;
	case __NR_waitid:
		strcpy(name, "__NR_waitid");
		break;
	case __NR_add_key:
		strcpy(name, "__NR_add_key");
		break;
	case __NR_request_key:
		strcpy(name, "__NR_request_key");
		break;
	case __NR_keyctl:
		strcpy(name, "__NR_keyctl");
		break;
	case __NR_ioprio_set:
		strcpy(name, "__NR_ioprio_set");
		break;
	case __NR_ioprio_get:
		strcpy(name, "__NR_ioprio_get");
		break;
	case __NR_inotify_add_watch:
		strcpy(name, "__NR_inotify_add_watch");
		break;
	case __NR_inotify_rm_watch:
		strcpy(name, "__NR_inotify_rm_watch");
		break;
#ifndef CONFIG_ARM
	case __NR_migrate_pages:
		strcpy(name, "__NR_migrate_pages");
		break;
#endif
	case __NR_openat:
		strcpy(name, "__NR_openat");
		break;
	case __NR_mkdirat:
		strcpy(name, "__NR_mkdirat");
		break;
	case __NR_mknodat:
		strcpy(name, "__NR_mknodat");
		break;
	case __NR_fchownat:
		strcpy(name, "__NR_fchownat");
		break;
#if !defined(CONFIG_ARM) && !defined(CONFIG_CSKY) 
	case __NR_newfstatat:
		strcpy(name, "__NR_newfstatat");
		break;
#endif
	case __NR_unlinkat:
		strcpy(name, "__NR_unlinkat");
		break;
	case __NR_renameat:
		strcpy(name, "__NR_renameat");
		break;
	case __NR_linkat:
		strcpy(name, "__NR_linkat");
		break;
	case __NR_symlinkat:
		strcpy(name, "__NR_symlinkat");
		break;
	case __NR_readlinkat:
		strcpy(name, "__NR_readlinkat");
		break;
	case __NR_fchmodat:
		strcpy(name, "__NR_fchmodat");
		break;
	case __NR_faccessat:
		strcpy(name, "__NR_faccessat");
		break;
	case __NR_pselect6:
		strcpy(name, "__NR_pselect6");
		break;
	case __NR_ppoll:
		strcpy(name, "__NR_ppoll");
		break;
	case __NR_unshare:
		strcpy(name, "__NR_unshare");
		break;
	case __NR_set_robust_list:
		strcpy(name, "__NR_set_robust_list");
		break;
	case __NR_get_robust_list:
		strcpy(name, "__NR_get_robust_list");
		break;
	case __NR_splice:
		strcpy(name, "__NR_splice");
		break;
	case __NR_tee:
		strcpy(name, "__NR_tee");
		break;
#if !defined(CONFIG_ARM) && !defined(CONFIG_CSKY) 
	case __NR_sync_file_range:
		strcpy(name, "__NR_sync_file_range");
		break;
#endif
	case __NR_vmsplice:
		strcpy(name, "__NR_vmsplice");
		break;
	case __NR_move_pages:
		strcpy(name, "__NR_move_pages");
		break;
	case __NR_utimensat:
		strcpy(name, "__NR_utimensat");
		break;
	case __NR_epoll_pwait:
		strcpy(name, "__NR_epoll_pwait");
		break;
	case __NR_timerfd_create:
		strcpy(name, "__NR_timerfd_create");
		break;
	case __NR_fallocate:
		strcpy(name, "__NR_fallocate");
		break;
	case __NR_timerfd_settime:
		strcpy(name, "__NR_timerfd_settime");
		break;
	case __NR_timerfd_gettime:
		strcpy(name, "__NR_timerfd_gettime");
		break;
	case __NR_accept4:
		strcpy(name, "__NR_accept4");
		break;
	case __NR_signalfd4:
		strcpy(name, "__NR_signalfd4");
		break;
	case __NR_eventfd2:
		strcpy(name, "__NR_eventfd2");
		break;
	case __NR_epoll_create1:
		strcpy(name, "__NR_epoll_create1");
		break;
	case __NR_dup3:
		strcpy(name, "__NR_dup3");
		break;
	case __NR_pipe2:
		strcpy(name, "__NR_pipe2");
		break;
	case __NR_inotify_init1:
		strcpy(name, "__NR_inotify_init1");
		break;
	case __NR_preadv:
		strcpy(name, "__NR_preadv");
		break;
	case __NR_pwritev:
		strcpy(name, "__NR_pwritev");
		break;
	case __NR_rt_tgsigqueueinfo:
		strcpy(name, "__NR_rt_tgsigqueueinfo");
		break;
	case __NR_perf_event_open:
		strcpy(name, "__NR_perf_event_open");
		break;
	case __NR_recvmmsg:
		strcpy(name, "__NR_recvmmsg");
		break;
	case __NR_fanotify_init:
		strcpy(name, "__NR_fanotify_init");
		break;
	case __NR_fanotify_mark:
		strcpy(name, "__NR_fanotify_mark");
		break;
	case __NR_prlimit64:
		strcpy(name, "__NR_prlimit64");
		break;
	case __NR_name_to_handle_at:
		strcpy(name, "__NR_name_to_handle_at");
		break;
	case __NR_open_by_handle_at:
		strcpy(name, "__NR_open_by_handle_at");
		break;
	case __NR_clock_adjtime:
		strcpy(name, "__NR_clock_adjtime");
		break;
	case __NR_syncfs:
		strcpy(name, "__NR_syncfs");
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	case __NR_setns:
		strcpy(name, "__NR_setns");
		break;
#endif
	case __NR_sendmmsg:
		strcpy(name, "__NR_sendmmsg");
		break;
#ifndef CONFIG_CSKY
	case __NR_process_vm_readv:
		strcpy(name, "__NR_process_vm_readv");
		break;
	case __NR_process_vm_writev:
		strcpy(name, "__NR_process_vm_writev");
		break;
#endif
	default:
		//printk("syscall numb is [%d]\n", numb);
		sprintf(name, "%d", numb);
		break;
	}
}

//static int send_audit_log(const char *path, const char *name, int result)
static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char* hash)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	//TODO
	//if (!is_allowed_send_log(result))
	//	return 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}
	//if (path) {
	//if (point) {
	//	//memcpy(sec_d->sub_name, path, strlen(path));
	//	memcpy(sec_d->sub_name, point->name, strlen(point->name));
	//} else {
	//	memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	//}
	memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	memcpy(sec_d->obj_name, name, strlen(name));
	//memset(sec_d->sub_hash, 0, LEN_HASH);
	memcpy(sec_d->sub_hash, hash, LEN_HASH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (point) {
		keraudit_log(TYPE_DMEASURE, point->type, result, sec_d, user,
			     current->pid);
	} else {
		keraudit_log(TYPE_DMEASURE, DMEASURE_OPERATE_PERIODICITY, result, sec_d,
			     user, current->pid);
	}

	kfree(sec_d);

out:
	return ret;
}

static int update_syscall(unsigned long *sys_call, int data_len)
{
	int ret = 0;
	int i = 0;
	struct dmeasure_feature_conf *dmeasure_feature = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	sys_m->syscall_addr = sys_call;
	sys_m->len_base = data_len;
	//memcpy(sys_m->base, sys_call, data_len);

	for (i = 0; i < NR_syscalls; i++) {
		sys_m->backup_syscall_table[i] = (unsigned long *)sys_call[i];
	}

	dmeasure_feature = get_dmeasure_feature_conf();
	if(dmeasure_feature->measure_mode)
		ret = set_measure_zone_to_tpcm(ACTION_NAME, (void *)sys_call, data_len);
	/* if (ret) { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm error !\n", */
	/* 	       __func__); */
	/* } else { */
	/* 	printk("Enter:[%s], set_measure_zone_to_tpcm success !\n", */
	/* 	       __func__); */
	/* } */

	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)sys_call, data_len);
	sm3_finish(&ctx, hash);
	print_hex(ACTION_NAME, hash, LEN_HASH);
	memcpy(sys_m->hash, hash, LEN_HASH);

	return ret;
}

static int backup_syscall(void)
{
	int ret = 0;
	unsigned long *sys_call = (unsigned long *)syscall_table;
	int data_len = NR_syscalls * sizeof(unsigned long);

	sys_m = kzalloc(sizeof(struct syscall_measure), GFP_KERNEL);
	if (!sys_m) {
		ret = -ENOMEM;
		goto out;
	}

	ret = update_syscall(sys_call, data_len);

	/* set_memory_unit(TYPE_SYSCALL_TABLE, DM_ACTION_SYSCALLTABLE_NAME, */
	/* 		(void *)sys_call, data_len); */
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], NR_syscalls:[%d]\n", __func__, NR_syscalls);
out:
	return ret;
}

int syscall_table_check(void *data)
{
	int ret = 0;
	int i = 0;
	char name[SYSCALL_NAME_LEN] = { 0 };
	unsigned long *sys_call = (unsigned long *)syscall_table;
	//char *path = NULL;
	struct dmeasure_point *point = NULL;
	struct module *mod = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	if (data) {
		//path = (char *)data;
		point = (struct dmeasure_point *)data;
	}

	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)sys_m->syscall_addr, sys_m->len_base);
	sm3_finish(&ctx, hash);

	//ret = memcmp(sys_m->syscall_addr, sys_m->base, sys_m->len_base);
	if (memcmp(hash, sys_m->hash, LEN_HASH) == 0) 
	{
		//send_audit_log(path, "syscall_table", RESULT_SUCCESS);
		send_audit_log(point, ACTION_NAME, RESULT_SUCCESS, hash);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure syscall table success!\n",
			__func__);
		goto out;
	}
	else
	{
		CriticalDataFailureCount_add();
		send_audit_log(point, ACTION_NAME, RESULT_FAIL, hash);
		//printk("Enter:[%s], dmeasure syscall table error!\n",__func__);
		ret = -EINVAL;
	}

	for (i = 0; i < NR_syscalls; i++) {
		if (sys_m->backup_syscall_table[i] != (unsigned long *)sys_call[i]) {
			get_syscall_name(i, name);
#if 1
			mod = get_module_from_addr(sys_call[i]);
			if (mod)
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure syscall table:[%s] error [%s]!\n", __func__, name, mod->name);
			else
				DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure syscall table:[%s] error!\n", __func__, name);
#else
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure syscall table:[%s] error!\n",
				__func__, name);
			//printk("[%s] backup:[0x%lx], now:[0x%lx]\n", name, (unsigned long)sys_m->backup_syscall_table[i], (unsigned long)sys_call[i]);
#endif
			//send_audit_log(path, name, RESULT_FAIL);
			//send_audit_log(point, name, RESULT_FAIL);
			//ret = -EINVAL;
		}
	}

out:
	return ret;
}

static struct dmeasure_node dsyscall_action = {
	.name = ACTION_NAME,
	.check = syscall_table_check,
};

int httc_syscall_init(void)
{
	int ret = 0;

	if (syscall_table == INVALID_DATA_FULL_FF || syscall_table == 0) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [SYSCALL] Argument Error!\n");
		ret = -EINVAL;
		goto out;
	} else {
		DEBUG_MSG(HTTC_TSB_DEBUG, "syscall_table:[%0lx]!\n", syscall_table);
	}

	//dmeasure_feature = get_dmeasure_feature_conf();

	ret = backup_syscall();
	if (ret)
		goto out;

	//if(dmeasure_feature->measure_mode)
	//{
	//	printk("dmeasure syscall using tpcm\n");
	//	goto out;
	//}

	//printk("dmeasure syscall using soft\n");
	dmeasure_register_action(DMEASURE_SYSCALL_ACTION, &dsyscall_action);

out:
	return ret;
}

void httc_syscall_exit(void)
{
	if (sys_m)
		kfree(sys_m);

	dmeasure_unregister_action(DMEASURE_SYSCALL_ACTION, &dsyscall_action);
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure syscall exit!\n");
	return;
}
