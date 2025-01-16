#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include "dmeasure_types.h"
#include "../policy/policy_dmeasure.h"
//#include "policy/list_dmeasure_trigger.h"
#include "sec_domain.h"
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
#include "version.h"
#include "function_types.h"
#include "log/log.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "utils/debug.h"

/*init filesystem value*/
static unsigned long filesystems = INVALID_DATA_FULL_FF;
static unsigned long filesystemslock = INVALID_DATA_FULL_FF;
static unsigned long superblocks = INVALID_DATA_FULL_FF;
static unsigned long sblock = INVALID_DATA_FULL_FF;
module_param(filesystems, ulong, 0644);
module_param(filesystemslock, ulong, 0644);
module_param(superblocks, ulong, 0644);
module_param(sblock, ulong, 0644);
MODULE_PARM_DESC(filesystems, "ulong file_systems address");
MODULE_PARM_DESC(filesystemslock, "ulong file_systems_lock address");
MODULE_PARM_DESC(superblocks, "ulong super_blocks address");
MODULE_PARM_DESC(sblock, "ulong sb_lock address");
/*end*/

static struct file_system_type *p_file_systems;
static rwlock_t *p_file_systems_lock;
static struct list_head *p_super_blocks;
static spinlock_t *p_sb_lock;

static DEFINE_MUTEX(dfsmeasure_lock);
static volatile int file_system_count;
static volatile int super_block_count;
static LIST_HEAD(file_system_list);
static LIST_HEAD(super_block_list);

struct filesystem_policy *filesystem_p = NULL;

//#define ACTION_NAME "FileSystem"
#define CIRCLE_NAME	"Periodicity"
#define ACTION_NAME DM_ACTION_FILESYSTEM_NAME

#define MAX_FILE_SYSTEM_NAME	64

struct super_block_info {
	struct list_head list;
	struct super_block *sb;
	char name[MAX_FILE_SYSTEM_NAME];
	char s_id[32];
	int status;
	const struct super_operations *s_op;
};

struct file_system_info {
	struct list_head list;
	struct file_system_type *fs;
	int status;
	char name[MAX_FILE_SYSTEM_NAME];
	int (*get_sb) (struct file_system_type *, int,
		       const char *, void *, struct vfsmount *);
	struct dentry *(*mount) (struct file_system_type *, int,
				 const char *, void *);
	void (*kill_sb) (struct super_block *);
};

static int kernel_args_addr_init(void)
{
	struct file_system_type **tmp;

	if (filesystems == INVALID_DATA_FULL_FF || filesystems == 0 ||
	    /*filesystemslock == INVALID_DATA_FULL_FF || filesystemslock == 0 ||*/
	    superblocks == INVALID_DATA_FULL_FF || superblocks == 0 ||
	    sblock == INVALID_DATA_FULL_FF || sblock == 0) {
			DEBUG_MSG(HTTC_TSB_INFO, "Insmod [FILESYSTEM] Argument Error!\n");
		return -EINVAL;
	} else {
			DEBUG_MSG(HTTC_TSB_DEBUG, "filesystems:[%0lx]!\n", filesystems);
			DEBUG_MSG(HTTC_TSB_DEBUG, "filesystemslock:[%0lx]!\n", filesystemslock);
			DEBUG_MSG(HTTC_TSB_DEBUG, "superblocks:[%0lx]!\n", superblocks);
			DEBUG_MSG(HTTC_TSB_DEBUG, "sblock:[%0lx]!\n", sblock);
	}

	tmp = (struct file_system_type **)filesystems;
	p_file_systems = *tmp;
	p_file_systems_lock = (rwlock_t *) filesystemslock;
	p_super_blocks = (struct list_head *)superblocks;
	p_sb_lock = (spinlock_t *) sblock;

	return 0;
}

static int fst_in_basedata(const char *name, unsigned len)
{
	struct file_system_info *fsi = NULL;

	list_for_each_entry(fsi, &file_system_list, list) {
		if (strlen(fsi->name) == len &&
		    strncmp(fsi->name, name, len) == 0) {
			return 1;
		}
	}

	return 0;
}

static struct file_system_info *file_system_info_by_fs(struct file_system_type
						       *fs)
{
	struct file_system_info *fsi = NULL;

	list_for_each_entry(fsi, &file_system_list, list) {
		if (fsi->fs == fs)
			return fsi;
	}

	return NULL;
}

static struct super_block_info *super_block_info_by_sb(struct super_block *sb)
{
	struct super_block_info *sbi = NULL;

	list_for_each_entry(sbi, &super_block_list, list) {
		if (sbi->sb == sb)
			return sbi;
	}

	return NULL;
}

static int add_super_block_info(struct super_block *sb)
{
	struct super_block_info *sbi;

	sbi = kzalloc(sizeof(struct super_block_info), GFP_ATOMIC);
	if (!sbi)
		return -ENOMEM;

	sbi->sb = sb;
	strncpy(sbi->name, sb->s_type->name, sizeof(sbi->name)-1);
	strncpy(sbi->s_id, sb->s_id, 31);
	sbi->s_op = sb->s_op;
	list_add(&sbi->list, &super_block_list);
	super_block_count++;

	if (!fst_in_basedata(sb->s_type->name, strlen(sb->s_type->name))) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "Superblock Name not in filesystem:[%s] s_id:[%s] addr:[%p]\n",
			sb->s_type->name, sb->s_id, sb);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Superblock Name:[%s, %s]\n",
			(sb->s_type->
				fs_flags & FS_REQUIRES_DEV) ? "dev" : "nodev",
			sb->s_type->name);
	}
	//printk("Add Superblock Name:[%s] s_id:[%s] addr:[%p]\n", sb->s_type->name, sb->s_id, sb);

	return 0;
}

static int remove_super_block_info(struct super_block *sb)
{
	struct super_block_info *sbi = NULL;

	list_for_each_entry(sbi, &super_block_list, list) {
		if (sbi->sb == sb) {
			list_del(&sbi->list);
			super_block_count--;
			DEBUG_MSG(HTTC_TSB_DEBUG, "Remove Super block name:[%s], s_id:[%s], addr:[%p]\n",
				sb->s_type->name, sb->s_id, sb);
			DEBUG_MSG(HTTC_TSB_DEBUG, "super_block_count:[%d]\n", super_block_count);
			kfree(sbi);
			break;
		}
	}

	return 0;
}

static void httc_kill_sb(struct super_block *sb)
{
	struct file_system_info *fsi = NULL;

	if (!sb || IS_ERR(sb)) {
		if (!sb) {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s] parameter 'sb' is null, now return\n",
				__func__);
		} else {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s] parameter 'sb' is IS_ERR status, now return\n",
				__func__);
		}
		return;
	}
	mutex_lock(&dfsmeasure_lock);
	fsi = file_system_info_by_fs(sb->s_type);
	if (!fsi)
		goto out;
	fsi->kill_sb(sb);
	remove_super_block_info(sb);
out:
	mutex_unlock(&dfsmeasure_lock);
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
struct dentry *httc_mount(struct file_system_type *fs_type,
			  int flags, const char *dev_name, void *data)
{
	struct dentry *ret = NULL;
	struct super_block *sb = NULL;
	struct file_system_info *fsi = NULL;

	mutex_lock(&dfsmeasure_lock);
	//read_lock(p_file_systems_lock);
	fsi = file_system_info_by_fs(fs_type);
	mutex_unlock(&dfsmeasure_lock);
	if (!fsi) {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], no file_system_info for fs:[%s]\n",
			__func__, fs_type->name);
		goto out_unlock;
	}

	ret = fsi->mount(fs_type, flags, dev_name, data);
	if (!ret || IS_ERR(ret)) {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s] Mount fs:[%s] failed!\n", __func__,
			fs_type->name);
		goto out_unlock;
	}

	mutex_lock(&dfsmeasure_lock);
	list_for_each_entry(sb, p_super_blocks, s_list) {
		if ((sb->s_type == fs_type) && !super_block_info_by_sb(sb)) {
			add_super_block_info(sb);
		}
	}
	mutex_unlock(&dfsmeasure_lock);

out_unlock:
	//read_unlock(p_file_systems_lock);
	//mutex_unlock(&dfsmeasure_lock);
	return ret;
}

#else
static int httc_get_sb(struct file_system_type *fs_type,
		       int flags, const char *dev_name, void *data,
		       struct vfsmount *mnt)
{
	int ret = 0;
	struct file_system_info *fsi;

	mutex_lock(&dfsmeasure_lock);
	//read_lock(p_file_systems_lock);
	fsi = file_system_info_by_fs(fs_type);
	if (!fsi) {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], no file_system_info for fs:[%s]\n",
			__func__, fs_type->name);
		goto out_unlock;
	}

	ret = fsi->get_sb(fs_type, flags, dev_name, data, mnt);
	if (ret || !mnt->mnt_sb) {
			DEBUG_MSG(HTTC_TSB_INFO, "Enter: [% s] Mount fs : [% s] failed!\n", __func__,
			fs_type->name);
		goto out_unlock;
	}

	if (!super_block_info_by_sb(mnt->mnt_sb)) {
		add_super_block_info(mnt->mnt_sb);
	}

out_unlock:
	//read_unlock(p_file_systems_lock);
	mutex_unlock(&dfsmeasure_lock);
	return ret;
}
#endif

static int add_file_system_info(struct file_system_type *fs)
{
	int ret = 0;
	struct file_system_info *fsi;

	fsi = kzalloc(sizeof(struct file_system_info), GFP_ATOMIC);
	if (!fsi)
		return -ENOMEM;

	fsi->fs = fs;
	strncpy(fsi->name, fs->name, sizeof(fsi->name)-1);

	list_add(&fsi->list, &file_system_list);
	file_system_count++;
	mb();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	fsi->mount = fs->mount;
	fs->mount = httc_mount;
#else
	fsi->get_sb = fs->get_sb;
	fs->get_sb = httc_get_sb;

#endif

	fsi->kill_sb = fs->kill_sb;
	fs->kill_sb = httc_kill_sb;

	DEBUG_MSG(HTTC_TSB_DEBUG, "Add Filesystem Name:[%s, %s]\n",
		(fs->fs_flags & FS_REQUIRES_DEV) ? "dev" : "nodev", fs->name);
	return ret;
}

static int add_all_filesystems_info(void)
{
	int ret = 0;
	struct file_system_type *fs;

	mutex_lock(&dfsmeasure_lock);
	//write_lock(p_file_systems_lock);
	fs = p_file_systems;
	while (fs) {
		if (!fst_in_basedata(fs->name, strlen(fs->name))) {
			add_file_system_info(fs);
		}
		fs = fs->next;
	}
	//write_unlock(p_file_systems_lock);
	mutex_unlock(&dfsmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], file_system_count:[%d]\n", __func__,
		file_system_count);
	return ret;
}

static void remove_all_filesystems_info(void)
{
	struct file_system_info *fsi, *tmp;

	mutex_lock(&dfsmeasure_lock);
	//write_lock(p_file_systems_lock);
	list_for_each_entry_safe(fsi, tmp, &file_system_list, list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		fsi->fs->mount = fsi->mount;
#else
		fsi->fs->get_sb = fsi->get_sb;
#endif
		fsi->fs->kill_sb = fsi->kill_sb;
		mb();
		list_del(&fsi->list);
		file_system_count--;
		kfree(fsi);
	}
	//write_unlock(p_file_systems_lock);
	mutex_unlock(&dfsmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], file_system_count:[%d]\n", __func__,
		file_system_count);
	return;
}

static int add_all_superblocks_info(void)
{
	struct super_block *sb = NULL;

	mutex_lock(&dfsmeasure_lock);
	spin_lock(p_sb_lock);
	list_for_each_entry(sb, p_super_blocks, s_list) {
		if (!super_block_info_by_sb(sb))
			add_super_block_info(sb);
	}
	spin_unlock(p_sb_lock);
	mutex_unlock(&dfsmeasure_lock);
	
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], super_block_count:[%d]\n", __func__,
		super_block_count);
	return 0;
}

static void remove_all_superblocks_info(void)
{
	struct super_block_info *sbi, *tmp;

	mutex_lock(&dfsmeasure_lock);
	list_for_each_entry_safe(sbi, tmp, &super_block_list, list) {
		list_del(&sbi->list);
		super_block_count--;
		kfree(sbi);
	}
	mutex_unlock(&dfsmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], super_block_count:[%d]\n", __func__,
		super_block_count);
	return;
}

static int dfilesystem_basedata_init(void)
{
	int ret = 0;

	ret = add_all_filesystems_info();
	if (ret)
		goto out;

	ret = add_all_superblocks_info();
	if (ret)
		goto out_superblocks;

	return ret;

out_superblocks:
	remove_all_filesystems_info();
out:
	return ret;
}

static void dfilesystem_basedata_exit(void)
{
	remove_all_filesystems_info();
	remove_all_superblocks_info();
}



//static int send_audit_log(const char *path, const char *name, int result)
static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char* hash)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}
	//if (path) {
	if (point) {
		//memcpy(sec_d->sub_name, path, strlen(path));
		memcpy(sec_d->sub_name, point->name, strlen(point->name));
	} else {
		memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	}
	memcpy(sec_d->obj_name, "filesystem(", strlen("filesystem("));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), name, strlen(name));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), ")", 1);
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

//static int file_system_list_check(char *path)
static int file_system_list_check(struct dmeasure_point *point)
{
	int ret = 0;
	struct file_system_info *fsi = NULL;
	struct file_system_type *fs = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	mutex_lock(&dfsmeasure_lock);
	//read_lock(p_file_systems_lock);
	list_for_each_entry(fsi, &file_system_list, list) {
		fs = fsi->fs;
		if (/*check_in_policy(fs->name)*/1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
			if (httc_mount == fs->mount &&
#else
			if (httc_get_sb == fs->get_sb &&
#endif
			    httc_kill_sb == fs->kill_sb) {
				//printk("dmeasure filesystem:[%s] ok!\n",
				//       fs->name);
				////send_audit_log(path, fs->name, RESULT_SUCCESS);
				//send_audit_log(point, fs->name, RESULT_SUCCESS);
			} else {
				sm3_init(&ctx);
				sm3_update(&ctx, (unsigned char *)fs->kill_sb, sizeof(fs->kill_sb));
				sm3_finish(&ctx, hash);

				DEBUG_MSG(HTTC_TSB_INFO, "dmeasure filesystem:[%s] err!\n", fs->name);
				//send_audit_log(path, fs->name, RESULT_FAIL);
				CriticalDataFailureCount_add();
				send_audit_log(point, fs->name, RESULT_FAIL, hash);
				ret = -EINVAL;
			}
		}
	}
	//read_unlock(p_file_systems_lock);
	mutex_unlock(&dfsmeasure_lock);

	if (!ret) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure filesystem success!\n", __func__);
		memset(hash, 0, LEN_HASH);
		send_audit_log(point, "file_system_type", RESULT_SUCCESS, hash);
	}

	return ret;
}

//static int super_block_list_check(char *path)
static int super_block_list_check(struct dmeasure_point *point)
{
	int ret = 0;
	struct super_block_info *sbi = NULL;
	struct super_block *sb = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	mutex_lock(&dfsmeasure_lock);
	spin_lock(p_sb_lock);
	list_for_each_entry(sbi, &super_block_list, list) {
		sb = sbi->sb;
		if (/*check_in_policy(sb->s_type->name)*/1) {
			if (sbi->s_op == sb->s_op) {
				//printk("dmeasure superblock:[%s][%s] ok!\n",
				//       sb->s_type->name, sb->s_id);
				////send_audit_log(path, sb->s_type->name, RESULT_SUCCESS);
				//send_audit_log(point, sb->s_type->name,
				//	       RESULT_SUCCESS);
			} else {
				sm3_init(&ctx);
				sm3_update(&ctx, (unsigned char *)sb->s_op, sizeof(sb->s_op));
				sm3_finish(&ctx, hash);

				DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure superblock:[%s][%s] err!\n", sb->s_type->name, sb->s_id);
				//send_audit_log(path, sb->s_type->name, RESULT_FAIL);
				CriticalDataFailureCount_add();
				send_audit_log(point, sb->s_type->name, RESULT_FAIL, hash);
				ret = -EINVAL;
			}
		}
	}
	spin_unlock(p_sb_lock);
	mutex_unlock(&dfsmeasure_lock);

	if (!ret) {
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure superblock success!\n", __func__);
		memset(hash, 0, LEN_HASH);
		send_audit_log(point, "super_block", RESULT_SUCCESS, hash);
	}

	return ret;
}

static int file_system_check(void *data)
{
	int ret1, ret2;
	//char *path = NULL;
	struct dmeasure_point *point = NULL;

	if (data) {
		//path = (char *)data;
		point = (struct dmeasure_point *)data;
	}
	//ret1 = file_system_list_check(path);
	ret1 = file_system_list_check(point);
	if (ret1) {
		DEBUG_MSG(HTTC_TSB_INFO, "file system check error!\n");
	}
	//ret2 = super_block_list_check(path);
	ret2 = super_block_list_check(point);
	if (ret2) {
		DEBUG_MSG(HTTC_TSB_INFO, "super_block check error!\n");
	}

	return ret1 ? ret1 : ret2;
}

static struct dmeasure_node dfilesystem_action = {
	.name = ACTION_NAME,
	.check = file_system_check,
};

int filesystem_init(void)
{
	int ret = 0;

	ret = kernel_args_addr_init();
	if (ret)
		goto out;

	ret = dfilesystem_basedata_init();
	if (ret) {
		ret = -EINVAL;
		goto out_basedata;
	}
//        get_filesystem_policy(filesystem_p);
	ret =
	    dmeasure_register_action(DMEASURE_FILESYSTEM_ACTION,
				     &dfilesystem_action);
	if (ret) {
		ret = -EINVAL;
		goto out_action;
	}

	return ret;

out_action:
	dfilesystem_basedata_exit();
out_basedata:
//        kfree(filesystem_p);
out:
	return ret;
}

void filesystem_exit(void)
{
	if (filesystem_p)
		kfree(filesystem_p);
	dmeasure_unregister_action(DMEASURE_FILESYSTEM_ACTION,
				   &dfilesystem_action);
	dfilesystem_basedata_exit();
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure filesystem exit!\n");
	return;
}
