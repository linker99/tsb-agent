
#ifndef VFS_UTILS_H_
#define VFS_UTILS_H_

enum {
	TYPE_FILE = 1,
	TYPE_INODE = 2,
	TYPE_DENTRY = 3,
	TYPE_TASK = 4,
};

int vfs_path_stat(const char *filename, struct kstat *stat);
//int vfs_filp_read(char *buf, int len, struct file *filp);
//int vfs_filp_write(char *buf, int len, struct file *filp);


char *vfs_get_fullpath(void *object, int type);
void vfs_put_fullpath(char *fullpath);
struct file *get_mm_exe_file(struct mm_struct *mm);
int find_ovl_inode_real(void);
#endif /* VFS_UTILS_H_ */

