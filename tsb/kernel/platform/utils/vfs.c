#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
//#include <asm/uaccess.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#endif
#include <linux/mount.h>
#include <linux/path.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#include <linux/lglock.h>
#endif

#include "vfs.h"
#include "../../include/version.h"
#include "debug.h"

// 24_02_26 针对 overlay 文件系统
#include <linux/kprobes.h>

int noop_pre_ovl(struct kprobe *p, struct pt_regs *regs) { return 0; }

static struct kprobe kp = {   
  .symbol_name = "ovl_inode_real",  
};

struct inode* (* ovl_inode_real_func )(struct inode *inode) = NULL;

struct inode *ovl_inode_real_httc(struct inode *inode){
  if (ovl_inode_real_func) {
    return ovl_inode_real_func(inode);
  }
  return inode;
}

int find_ovl_inode_real(void)
{ 
  int ret;
  kp.pre_handler = noop_pre_ovl;
  ret = register_kprobe(&kp);
  if (ret < 0) {  
    DEBUG_MSG(HTTC_TSB_INFO,"register_kprobe failed, error:%d\n", ret); 
    return ret; 
  }
  DEBUG_MSG(HTTC_TSB_DEBUG,"ovl_inode_real :%p\n", kp.addr); 
  ovl_inode_real_func = (void*)kp.addr; 
  unregister_kprobe(&kp);
  return ret;
}


// 24_02_26 end

int vfs_path_stat(const char *filename, struct kstat *stat)
{
#ifdef set_fs
	mm_segment_t oldfs;
#endif
	int error=0;

#ifdef set_fs
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	error = vfs_stat((char *)filename, stat);

#endif
#ifdef set_fs
	set_fs(oldfs);
#endif

	return error;
}
EXPORT_SYMBOL(vfs_path_stat);


#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0))
ssize_t vfs_read_no_check(struct file *file, char __user *buf, size_t count, loff_t *pos)
 {
         ssize_t ret;

         if (!(file->f_mode & FMODE_READ))
                 return -EBADF;
         if (!file->f_op || (!file->f_op->read && !file->f_op->aio_read))
                 return -EINVAL;

		 if (file->f_op->read)
				 ret = file->f_op->read(file, buf, count, pos);
		 else
				 ret = do_sync_read(file, buf, count, pos);
//		 if (ret > 0) {
//				 fsnotify_access(file->f_dentry);
//				 current->rchar += ret;
//		 }
//		 current->syscr++;

         return ret;
 }

 ssize_t vfs_write_no_check(struct file *file, const char __user *buf, size_t count, loff_t *pos)
 {
         ssize_t ret;

         if (!(file->f_mode & FMODE_WRITE))
                 return -EBADF;
         if (!file->f_op || (!file->f_op->write && !file->f_op->aio_write))
                 return -EINVAL;
//         if (unlikely(!access_ok(VERIFY_READ, buf, count)))
//                 return -EFAULT;
//
//         ret = rw_verify_area(WRITE, file, pos, count);
//         if (ret >= 0) {
//                 count = ret;
//                 ret = security_file_permission (file, MAY_WRITE);
//                 if (!ret) {
		 if (file->f_op->write)
				 ret = file->f_op->write(file, buf, count, pos);
		 else
				 ret = do_sync_write(file, buf, count, pos);
//                         if (ret > 0) {
//                                 fsnotify_modify(file->f_dentry);
//                                 current->wchar += ret;
//                         }
//                         current->syscw++;
//                 }
//         }

         return ret;
}
#endif



 struct mount {
	 struct list_head mnt_hash;
	 struct mount *mnt_parent;
	 struct dentry *mnt_mountpoint;
	 struct vfsmount mnt;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
	 struct rcu_head mnt_rcu;
#endif
#ifdef CONFIG_SMP
	 struct mnt_pcp __percpu *mnt_pcp;
#else
	 int mnt_count;
	 int mnt_writers;
#endif
	 struct list_head mnt_mounts;	/* list of children, anchored here */
	 struct list_head mnt_child;	/* and going through their mnt_child */
	 struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	 const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	 struct list_head mnt_list;
	 struct list_head mnt_expire;	/* link in fs-specific expiry list */
	 struct list_head mnt_share;	/* circular list of shared mounts */
	 struct list_head mnt_slave_list;	/* list of slave mounts */
	 struct list_head mnt_slave;	/* slave list entry */
	 struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	 struct mnt_namespace *mnt_ns;	/* containing namespace */
	 struct mountpoint *mnt_mp;	/* where is it mounted */
#ifdef CONFIG_FSNOTIFY
	 struct hlist_head mnt_fsnotify_marks;
	 __u32 mnt_fsnotify_mask;
#endif
	 int mnt_id;		/* mount identifier */
	 int mnt_group_id;	/* peer group identifier */
	 int mnt_expiry_mark;	/* true if marked for expiry */
	 int mnt_pinned;
	 int mnt_ghosts;
 };

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)

struct file *get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
	rcu_read_unlock();
	return exe_file;
}

EXPORT_SYMBOL(get_mm_exe_file);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
struct file *get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
	return exe_file;
}

EXPORT_SYMBOL(get_mm_exe_file);
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
extern seqlock_t *pmount_lock;

static inline struct vfsmount *find_vfsmount(struct dentry *dentry)
{
	struct mount *mnt;
	struct vfsmount *vfsmount;
	unsigned int seq;

	rcu_read_lock();
	do {
		vfsmount = 0;
		seq = read_seqbegin(pmount_lock);
		list_for_each_entry_rcu(mnt, &dentry->d_sb->s_mounts,
			mnt_instance) {
				if (dentry->d_sb->s_root == mnt->mnt.mnt_root) {
					vfsmount = &mnt->mnt;
					break;
				}
		}
	} while (read_seqretry(pmount_lock, seq));
	rcu_read_unlock();

	return vfsmount;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
extern struct lglock *pmount_lock;

static void inline vfsmount_read_lock(void)
{
	if (pmount_lock)
		br_read_lock(pmount_lock);
}

static void inline vfsmount_read_unlock(void)
{
	if (pmount_lock)
		br_read_unlock(pmount_lock);
}

static inline struct vfsmount *find_vfsmount(struct dentry *dentry)
{
	struct mount *mnt;
	struct vfsmount *vfsmount = 0;

	vfsmount_read_lock();
	list_for_each_entry(mnt, &dentry->d_sb->s_mounts, mnt_instance) {
		if (dentry->d_sb->s_root == mnt->mnt.mnt_root) {
			vfsmount = &mnt->mnt;
			break;
		}
	}
	vfsmount_read_unlock();
	return vfsmount;
}
#else
static struct vfsmount *do_find_mount(struct vfsmount *cmnt,
struct dentry *d_root)
{
	struct vfsmount *mnt;

	if (cmnt->mnt_root == d_root) {
		return cmnt;
	}

	list_for_each_entry(mnt, &cmnt->mnt_mounts, mnt_child) 
	{
		struct vfsmount* tmnt;
		if ((tmnt = do_find_mount(mnt, d_root)))
			return tmnt;
	}
	return 0;
}

static inline struct vfsmount *find_vfsmount(struct dentry *dentry)
{
	return do_find_mount(current->fs->root.mnt, dentry->d_sb->s_root);
}
#endif

static inline long __must_check IS_ERR_OR_NUL(const void *ptr)
{
	return !ptr || IS_ERR(ptr);
}

int suffix_match(char *string, char *pattern)
{
	int slen = 0;
	int plen = 0;
	int offset = 0;

	if (string == NULL || pattern == NULL)
		return -1;

	slen = strlen(string);
	plen = strlen(pattern);

	if (plen == 0)
		return 0;

	if (plen > slen)
		return 1;

	offset = slen - plen;

	return memcmp(string + offset, pattern, plen);
}

int kerctl_dgetpath(struct dentry *dentry, char *fullpath, int path_len);

int is_overlay_fs_inode(struct inode *in)
{
	if(IS_ERR_OR_NUL(in)){
		return -1;
	}
	if(IS_ERR_OR_NUL( in->i_sb)){
		return -1;
	}
	if(strcmp(in->i_sb->s_id, "overlay")){
		return -1;
	}
	return 0;
} 
char *overlay_fs_fullpath(struct inode *in, char *buf, size_t size)
{
	int ret = 0;
	struct dentry *d_dentry = NULL;
	in = ovl_inode_real_httc(in);
    if (IS_ERR_OR_NUL(in)) {
		return NULL;
	}
  	d_dentry = d_find_alias(in);
    if (IS_ERR_OR_NUL(d_dentry)) {
		return NULL;
	}
    ret = kerctl_dgetpath(d_dentry, buf, size);
  dput(d_dentry);
	if(ret){
		return NULL;
	}
	return buf;
}
int kerctl_tgetpath(struct task_struct *task, char *fullpath, int path_len)
{
	int ret = 0;
	struct mm_struct *mm = get_task_mm(task);
	struct file *exec_file = NULL;
  struct inode * in = NULL;

	char *buf = NULL;
	char *ptr = NULL;
	int len;

	if (!mm) {
		//DEBUG_MSG(HTTC_TSB_INFO, "[%s] task mm is NULL\n", __func__);
		ret = -EINVAL;
		goto err;
	}

	exec_file = get_mm_exe_file(mm);
	if (!exec_file) {
		//DEBUG_MSG(HTTC_TSB_INFO, "[%s] get_mm_exe_file error\n", __func__);
		ret = -EINVAL;
		goto err_exe;
	}

	buf = kzalloc(path_len, GFP_KERNEL);
	if (!buf) {
		//DEBUG_MSG(HTTC_TSB_INFO, "[%s] kzalloc error\n", __func__);
		ret = -ENOMEM;
		goto err_mem;
	}

  	in = file_inode(exec_file);
  	if(is_overlay_fs_inode(in) == 0 ){
	  	ptr = overlay_fs_fullpath(in, buf, path_len);
 	 } else {
		ptr = d_path(&exec_file->f_path, buf, path_len);
  	}
	  
	if (IS_ERR_OR_NUL(ptr)) {
		//DEBUG_MSG(HTTC_TSB_INFO, "[%s] fullpath ptr is error\n", __func__);
		ret = -EINVAL;
		goto err_path;
	}

	
	/*filter path include (deleted) */
	len = strlen(ptr);
	if (suffix_match(ptr, " (deleted)") == 0) {
		len = len - strlen(" (deleted)");
		memcpy(fullpath, ptr, len);
		fullpath[len] = '\0';
	} else {
		memcpy(fullpath, ptr, len);
	}

err_path:
	if (buf)
		kfree(buf);
err_mem:
	fput(exec_file);
err_exe:
	mmput(mm);
err:
	return ret;
}

char *get_fullpath_from_task(struct task_struct *task)
{
	int ret = 0;
	char *fullpath;

	fullpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!fullpath) {
		DEBUG_MSG(HTTC_TSB_INFO,"[%s] kzalloc error\n", __func__);
		return NULL;
	}

	ret = kerctl_tgetpath(task, fullpath, PATH_MAX);
	if (ret == 0) {
		return fullpath;
	} else {
		kfree(fullpath);
		return NULL;
	}
}

static int kerctl_fgetpath(struct file *file, char *fullpath, int path_len)
{
	int ret = 0;
	struct path path;
	char *buf;
	char *ptr = NULL;
	int len = 0;

	buf = kzalloc(path_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
  
	path = file->f_path;

	ptr = d_path(&path, buf, path_len);
	if (IS_ERR_OR_NUL(ptr)) {
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], name:[%s]!\n", __func__, path.dentry->d_name.name);
		ret = -EINVAL;
		goto err;
	}

	len = strlen(ptr);
	memcpy(fullpath, ptr, len);

err:
	if (buf)
		kfree(buf);
	return ret;
}

char *get_fullpath_from_inode(struct inode *inode);

static char *get_fullpath_from_file(struct file *file)
{
	int ret = 0;
	char *fullpath = NULL;
  	struct inode * in;
  
  in = file_inode(file);
  if (!IS_ERR_OR_NUL(in) &&  !IS_ERR_OR_NUL(in->i_sb) && strcmp(in->i_sb->s_id,"overlay") == 0) {
    return get_fullpath_from_inode(in);
  }

	fullpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!fullpath)
		return NULL;

	ret = kerctl_fgetpath(file, fullpath, PATH_MAX);

	if (ret == 0) {
		return fullpath;
	} else {
		kfree(fullpath);
		return NULL;
	}
}

int kerctl_dgetpath(struct dentry *dentry, char *fullpath, int path_len)
{
	int ret = 0;
	char *buf;
	char *ptr = NULL;
	struct vfsmount *mnt = NULL;
	struct path path;
	int len = 0;

	buf = kzalloc(path_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mnt = find_vfsmount(dentry);
	if (!mnt) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], find_vfsmount, fs_type:[%s], name:[%s]!\n",
			__func__, dentry->d_sb->s_type->name,
			dentry->d_name.name);
		ret = -EINVAL;
		goto err;
	}

	path.dentry = dentry;
	path.mnt = mnt;
	ptr = d_path(&path, buf, path_len);
	if (IS_ERR_OR_NUL(ptr)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], d_path, name:[%s]!\n", __func__,
			dentry->d_name.name);
		ret = -EINVAL;
		goto err;
	}
	/*filter path include (deleted) */
	len = strlen(ptr);
	if (suffix_match(ptr, " (deleted)") == 0) {
		len = len - strlen(" (deleted)");
		memcpy(fullpath, ptr, len);
		fullpath[len] = '\0';
	} else {
		memcpy(fullpath, ptr, len);
	}

err:
	if (buf)
		kfree(buf);
	return ret;
}

char *get_fullpath_from_inode(struct inode *inode)
{
	int ret = 0;
	char *fullpath;
	struct dentry *d_dentry = NULL;
  struct super_block	*sb = NULL;
  struct inode *inode_tmp = NULL;

	fullpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!fullpath)
		return NULL;

  sb = inode->i_sb;
  if ( !IS_ERR_OR_NUL(sb) && strcmp(sb->s_id,"overlay") == 0) {
    inode_tmp = ovl_inode_real_httc(inode);
    if (!IS_ERR_OR_NUL(inode_tmp)) {
      inode = inode_tmp; 
    }
  }

	d_dentry = d_find_alias(inode);
	if (!d_dentry)
		goto out;

	ret = kerctl_dgetpath(d_dentry, fullpath, PATH_MAX);
	if (ret == 0) {
		dput(d_dentry);
		return fullpath;
	}
	dput(d_dentry);

out:
	if (fullpath)
		kfree(fullpath);
	return NULL;
}

char *get_fullpath_from_dentry(struct dentry *dentry)
{
	int ret = 0;
	char *fullpath;

	fullpath = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!fullpath)
		return NULL;

	ret = kerctl_dgetpath(dentry, fullpath, PATH_MAX);
	if (ret == 0) {
		return fullpath;
	} else {
		kfree(fullpath);
		return NULL;
	}
}

char *vfs_get_fullpath(void *object, int type)
{
	char *fullpath = NULL;

	switch (type) {
	case TYPE_TASK:
		fullpath = get_fullpath_from_task((struct task_struct *)object);
		/* if (!fullpath) { */
		/* 	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get full path from task error!\n", */
		/* 	       __func__); */
		/* } */
		break;
	case TYPE_FILE:
		fullpath = get_fullpath_from_file((struct file *)object);
		/* if (!fullpath) { */
		/* 	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get full path from file error!\n", */
		/* 	       __func__); */
		/* } */
		break;
	case TYPE_INODE:
		fullpath = get_fullpath_from_inode((struct inode *)object);
		/* if (!fullpath) { */
		/* 	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get full path from inode error!\n", */
		/* 	       __func__); */
		/* } */
		break;
	case TYPE_DENTRY:
		fullpath = get_fullpath_from_dentry((struct dentry *)object);
		/* if (!fullpath) { */
		/* 	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get full path from dentry error!\n", */
		/* 	       __func__); */
		/* } */
		break;
	default:
		DEBUG_MSG(HTTC_TSB_INFO,"[%s] get fullpath type[%d] error!\n", __func__, type);
		break;
	}

	return fullpath;
}
EXPORT_SYMBOL(vfs_get_fullpath);

void vfs_put_fullpath(char *fullpath)
{
	if (fullpath) 
	{
		kfree(fullpath);
	}
}
EXPORT_SYMBOL(vfs_put_fullpath);
