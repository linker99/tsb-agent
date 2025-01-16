

#ifndef SRC_VERSION_H_
#define SRC_VERSION_H_
#include <linux/version.h>
#include <asm/unistd.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/desc.h>
#endif
#include <linux/err.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#include <linux/path.h>
#endif

#if !defined(NR_syscalls)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#include <asm/asm-offsets.h>
#else
#define NR_syscalls (__NR_syscall_max + 1)
#endif
#endif


#define NEWLIST_VERSION_MAJOR   3
#define NEWLIST_VERSION_MINOR   9
#if (LINUX_VERSION_CODE < KERNEL_VERSION(NEWLIST_VERSION_MAJOR, NEWLIST_VERSION_MINOR, 0))
    #define HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) hlist_for_each_entry(tpos, pos, head, member)
#else
    #define HLIST_FOR_EACH_ENTRY(tpos, pos, head, member) hlist_for_each_entry(tpos, head, member)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(NEWLIST_VERSION_MAJOR, NEWLIST_VERSION_MINOR, 0))
    #define HLIST_FOR_EACH_ENTRY_SAFE(tpos, pos, n, head, member) hlist_for_each_entry_safe(tpos, pos, n, head, member)
#else
    #define HLIST_FOR_EACH_ENTRY_SAFE(tpos, pos, n, head, member) hlist_for_each_entry_safe(tpos, n, head, member)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(NEWLIST_VERSION_MAJOR, NEWLIST_VERSION_MINOR, 0))
    #define HLIST_DEL(entry, node, member) hlist_del(node)
#else
    #define HLIST_DEL(entry, node, member) hlist_del(&entry->member)
#endif



#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
   struct dentry;
   struct vfsmount;

   struct path {
           struct vfsmount *mnt;
          struct dentry *dentry;
   };

static inline void path_get(struct path *path)
{
	mntget(path->mnt);
	dget(path->dentry);
}

/**
* path_put - put a reference to a path
* @path: path to put the reference to
*
* Given a path decrement the reference count to the dentry and the vfsmount.
*/
static inline void path_put(struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}

#endif


//static inline char *httcsec_version_dpath4(struct dentry *dentry, struct vfsmount *vfsmnt,char *buf, int buflen){
//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
//	return d_path(dentry,vfsmnt,buf,buflen);
//#else
//	struct path path = {vfsmnt,dentry};
//	return d_path(&path,buf,buflen);
//#endif
//
//}
//
//
//static inline char *httcsec_version_dpath3(struct path *path,char *buf, int buflen){
//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
//	return d_path(path->dentry,path->mnt,buf,buflen);
//#else
//	return d_path(path,buf,buflen);
//#endif
//
//}


//syscall
#if !defined(NR_syscalls)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#define NR_syscalls (__NR_syscall_max + 1)
#endif
#endif

//static inline long __must_check IS_ERR_OR_NUL(const void *ptr)
//{
//         return !ptr || IS_ERR_VALUE((unsigned long)ptr);
//}


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#define INET_SADDR(sock) (sock)->saddr
#define INET_SPORT(sock) (sock)->sport
#define INET_DADDR(sock) (sock)->daddr
#define INET_DPORT(sock) (sock)->dport
#define INET_NUM(inet) (inet)->num

#else
#define INET_SADDR(sock) (sock)->inet_saddr
#define INET_SPORT(sock) (sock)->inet_sport
#define INET_DADDR(sock) (sock)->inet_daddr
#define INET_DPORT(sock) (sock)->inet_dport
#define INET_NUM(inet) (inet)->inet_num
#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)

static inline void store_idt(struct desc_ptr *dtr)
{
        asm volatile("sidt %0":"=m" (*dtr));
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
static inline struct new_utsname *utsname(void){
	return &system_utsname;
}
static inline struct task_struct *pid_to_task(pid_t pid){
	return find_task_by_pid_type(PIDTYPE_PID, pid);
}
#else
static inline struct task_struct *pid_to_task(pid_t pid){
	return pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
}
#endif

#endif /* SRC_VERSION_H_ */
