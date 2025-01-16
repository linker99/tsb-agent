#include <linux/version.h>
#include <linux/rtc.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/security.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#endif
#include "sec_domain.h"
#include "utils/vfs.h"
#include "utils/debug.h"
#include "engine/engine.h"
#include "../policy/policy_fac_cache.h"
#include "../policy/list_fac.h"
#include "policy/feature_configure.h"
#include "../policy/hash_whitelist_path.h"
#include "version.h"
#include "tpcm/tpcmif.h"
#include "log/log.h"
#include "tsbapi/tsb_log_notice.h"

struct httcsec_intercept_module *global_old_hook = NULL;
struct httcsec_intercept_module *global_self_hook = NULL;

static volatile int g_fac_switch = 1;

extern int dmeasure_trigger_action(unsigned long i_ino, int type);


#define SUPER_PATH	"/usr/local/httcsec/"
int is_super_process(const char *fullpath)
{
	int ret = 0;

	if (!strncmp(fullpath, SUPER_PATH, strlen(SUPER_PATH)))
		ret = 1;

	return ret;
}

static int special_type_filter(struct inode *inode)
{
	if (special_file(inode->i_mode))
		return 1;
	if (!(inode->i_sb))
		return 0;
	if (!(inode->i_sb->s_type))
		return 0;
	if ((!strcmp(inode->i_sb->s_type->name, "pipefs")) ||
	    (!strcmp(inode->i_sb->s_type->name, "sockfs")) ||
	    (!strcmp(inode->i_sb->s_type->name, "anon_inodefs")) ||
	    (!strcmp(inode->i_sb->s_type->name, "inotifyfs"))) {
		return 1;
	}
	return 0;
}

static int file_filter(struct file *file)
{
	if (!file ||
	    !(file->f_path.dentry) ||
	    !(file->f_path.dentry->d_inode) /*||
	    S_ISDIR(file->f_path.dentry->d_inode->i_mode)*/)  //¨¨£¤¦Ì?????1y??¨¬??t¡ê¡§?¨®¨¦?¡ä?1y???¨¢¦Ì????????????¨¢¡À¡ê?¡è2???¨º¡À?T¡¤¡§????ls¡¤??¨º¡À¡ê?¡è????¡ê?
		return 1;

	if (special_type_filter(file->f_path.dentry->d_inode))
		return 1;

	return 0;
}

//static int inode_filter(struct inode *inode)
//{
//	if (!inode || S_ISDIR(inode->i_mode))
//		return 1;
//
//	if (special_type_filter(inode))
//		return 1;
//
//	return 0;
//}

static int dentry_filter(struct dentry *dentry)
{
	if (!dentry || !(dentry->d_inode))
		return 1;

	if (special_type_filter(dentry->d_inode))
		return 1;

	return 0;
}

static int access_control(void *object, int type, int mask, const char *func, int cache, int is_file_open)
{
	int ret = 0;
	struct sec_domain *sec_d = NULL;
	unsigned int user = 0;
	char *filename = NULL;
	int name_len = 0;

	int path_len = 0;
	char *taskpath = NULL;
	struct task_struct *tsk = current;

	if(is_empty_mac_policy() == 0){
		goto pass;	
	}

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		goto pass;
	}

	taskpath = vfs_get_fullpath(tsk, TYPE_TASK);
	if (!taskpath) {
		if(strcmp("kdevtmpfs",tsk->comm) == 0){
			;
		}else{
			DEBUG_MSG(HTTC_TSB_INFO, "[%s] get [%s] fullpath error!\n", __func__, tsk->comm);
		}
		goto pass;
	}
	path_len = strlen(taskpath);
	if (path_len < LEN_NAME_MAX) {
		memcpy(sec_d->sub_name, taskpath, path_len);
		sec_d->sub_len = path_len;
	} else {
		memcpy(sec_d->sub_name, taskpath, LEN_NAME_MAX);
		sec_d->sub_len = LEN_NAME_MAX;
	}
	if(is_super_process(taskpath))
		goto pass;

	filename = vfs_get_fullpath(object, type);
	if (!filename) {
		DEBUG_MSG(HTTC_TSB_INFO, "[%s] get file name error [pass]!\n", __func__);
		goto pass;
	}
	name_len = strlen(filename);
	sec_d->obj_len = (name_len > LEN_NAME_MAX) ? LEN_NAME_MAX : name_len;
	memcpy(sec_d->obj_name, filename, sec_d->obj_len);
	sec_d->start_time = 0;
	sec_d->end_time = 0;
	sec_d->result = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	ret = query_whitelist_path(sec_d, 0);
	if(!ret) {
		ret = -EACCES;
		DEBUG_MSG(HTTC_TSB_INFO, "[%s], sub_name[%s] obj_name[%s] exist in whitelist path\n", __func__, sec_d->sub_name, sec_d->obj_name);
		goto out;
	}

	ret = query_fac_policy_state(sec_d, 0);
	if ((ret==0) && (mask & OPERATE_RENAME)) {
		/* dir protect: rename(mv) */
		struct dentry *dentry = (struct dentry *)object;
		if (S_ISDIR(dentry->d_inode->i_mode)) {
			ret = query_dir_segment_fac_policy_state(sec_d, 0);
			DEBUG_MSG(HTTC_TSB_DEBUG, "[%s] mask[0x%x] sub_name[%s] obj_name[%s] query_dir_segment_fac_policy_state ret[%d]!\n", __func__, mask, sec_d->sub_name, sec_d->obj_name, ret);
		}
	}

out:
	if (ret == 0) {
		keraudit_log(LOG_CATEGRORY_ACCESS, mask, RESULT_SUCCESS, sec_d, user, current->pid);	//success audit log
		//if (printk_ratelimit())
			DEBUG_MSG(HTTC_TSB_DEBUG, "[%s], comm[%s][%d], parent[%s][%d], [%s][%s]-[%d] SUCCESS\n",
				  func, current->comm, current->pid, current->parent->comm, current->parent->pid, sec_d->sub_name, sec_d->obj_name, mask);
	} else {
		keraudit_log(LOG_CATEGRORY_ACCESS, mask, RESULT_FAIL, sec_d, user, current->pid);	//fail audit log
		//if (printk_ratelimit())
			DEBUG_MSG(HTTC_TSB_DEBUG, "[%s], comm[%s][%d], parent[%s][%d], [%s][%s]-[%d] FAIL\n",
				  func, current->comm, current->pid, current->parent->comm, current->parent->pid, sec_d->sub_name, sec_d->obj_name, mask);
	}
pass:
	if (sec_d)
		kfree(sec_d);
	if (taskpath)
		vfs_put_fullpath(taskpath);
	if (filename)
		vfs_put_fullpath(filename);
	return ret;
}

static int httc_verify_permission(void *object, int type, int mask, const char *func, int cache)
{
	int ret = 0;

	ret = access_control(object, type, mask, func, cache, 0);
	if (ret)
		FileAccessCount_add();

	if(ret)
		ret = -EACCES;

	return ret;
}

//static int httc_file_permission(void *object, int type, int mask, const char *func)
//{
//	int operate = 0;
//
//	/* only check write, append */
//	operate |= (mask & MAY_WRITE) ? (OPERATE_WRITE) : 0;
//	operate |= (mask & MAY_APPEND) ? (OPERATE_APPEND) : 0;
//	if (!operate)
//		return 0;
//
//	switch (type) {
//	case TYPE_FILE:
//		/* special file filter */
//		if (file_filter((struct file *)object))
//			return 0;
//		break;
//	case TYPE_INODE:
//		/* special inode filter */
//		if (inode_filter((struct inode *)object))
//			return 0;
//		break;
//	default:
//		printk("[%s] get type error, type[%d]!\n", func, type);
//		return 0;
//	}
//
//	return httc_verify_permission(object, type, operate, func, 1);
//}

static int httc_dentry_permission(struct dentry *dentry, int mask, const char *func)
{
	/* do not check read */
	if (mask & OPERATE_READ)
		return 0;

	if (!(mask & OPERATE_CREATE)) {
		if (dentry_filter(dentry))
			return 0;
	}

	return httc_verify_permission((void *)dentry, TYPE_DENTRY, mask, func, 0);
}

//static int smeasure_file_permission(struct file *file, int mask)
//{
//	return httc_file_permission((void *)file, TYPE_FILE, mask, __func__);
//}
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
//static int smeasure_inode_permission(struct inode *inode, int mask, unsigned flags)
//#else
//static int smeasure_inode_permission(struct inode *inode, int mask)
//#endif
//{
//	int ret = 0;
//
//	ret = httc_file_permission((void *)inode, TYPE_INODE, mask, __func__);
//	if (ret)
//		goto out;
//
//	/* file open trigger dmeasure */
//	//if (mask & MAY_OPEN) {
//	//	ret = dmeasure_trigger_action(inode->i_ino, FILE_TRIGGER);
//	//}
//
//out:
//	return ret;
//}
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
//static int smeasure_inode_getattr(const struct path *path)
//{
//	return httc_dentry_permission(path->dentry, OPERATE_READ, __func__);
//}
//#else
//static int smeasure_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
//{
//	return httc_dentry_permission(dentry, OPERATE_READ, __func__);
//}
//#endif
//
//static int smeasure_inode_setattr(struct dentry *dentry, struct iattr *iattr)
//{
//	int ret = 0;
//	unsigned int ia_valid = iattr->ia_valid;
//
//	/* ATTR_FORCE is just used for ATTR_KILL_S[UG]ID. */
//	if (ia_valid & ATTR_FORCE) {
//		ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_MODE | ATTR_FORCE);
//		if (!ia_valid)
//			return 0;
//	}
//
//	ret = httc_dentry_permission(dentry, OPERATE_WRITE, __func__);
//
//	return ret;
//}

static int smeasure_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
	int ret = 0;

	if(!g_fac_switch)
		return 0;

	ret = httc_dentry_permission(old_dentry, OPERATE_WRITE, __func__);

	if (ret == 0)
		ret = httc_dentry_permission(new_dentry, OPERATE_WRITE, __func__);

	return ret;
}

static int smeasure_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int ret=0;
	if(!g_fac_switch)
		return 0;

	if(global_old_hook != NULL && global_old_hook->inode_unlink != NULL)
	{
		ret = global_old_hook->inode_unlink(dir, dentry);
		if(ret)
			return ret;
	}

	if(ret==0)
	{
		ret=httc_dentry_permission(dentry, OPERATE_DELETE, __func__);
	}

	return ret;
}

static int smeasure_inode_rename(struct inode *old_inode,
				 struct dentry *old_dentry,
				 struct inode *new_inode,
				 struct dentry *new_dentry)
{
	int ret = 0;

	if(!g_fac_switch)
		return 0;

	ret = httc_dentry_permission(old_dentry, OPERATE_RENAME, __func__);
	if (!ret) {
		ret = httc_dentry_permission(new_dentry, OPERATE_CREATE, __func__);
	}

	return ret;
}

static int smeasure_inode_create(struct inode *dir, struct dentry *dentry,
				 int mode)
{
	if(!g_fac_switch)
		return 0;

	return httc_dentry_permission(dentry, OPERATE_CREATE, __func__);
}

static int smeasure_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if(!g_fac_switch)
		return 0;

	return httc_dentry_permission(dentry, OPERATE_DELETE, __func__);
}

static int smeasure_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
	if(!g_fac_switch)
		return 0;

	return httc_dentry_permission(dentry, OPERATE_CREATE, __func__);
}

#define FILE_OPEN_MAGIC 0xab12ddef
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
static int smeasure_fac_file_open(struct file *file)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static int smeasure_fac_file_open(struct file *file, const struct cred *cred)
#else
static int smeasure_fac_dentry_open(struct file *file, const struct cred *cred)
#endif
{
	int ret = 0;
	unsigned int user = 0;
	int mask = 0;
	struct sec_domain *sec_d = NULL;
	char *filename = NULL;
	int name_len = 0;
	int path_len = 0;
	char *taskpath = NULL;
	struct task_struct *tsk = current;

	if(!g_fac_switch)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	if(global_old_hook != NULL && global_old_hook->file_open != NULL)
#else
	if(global_old_hook != NULL && global_old_hook->dentry_open != NULL)
#endif
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
		ret = global_old_hook->file_open(file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		ret = global_old_hook->file_open(file, cred);
#else
		ret = global_old_hook->dentry_open(file, cred);
#endif
		if(ret)
			return ret;
	}

	if (file_filter(file))
		return 0;

	if(*(end_of_stack(current)+1) == FILE_OPEN_MAGIC)
		return 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		goto pass;
	}

	taskpath = vfs_get_fullpath(tsk, TYPE_TASK);
	if (!taskpath) {
		//printk("[%s] get [%s] fullpath error!\n", __func__, tsk->comm);
		goto pass;
	}
	path_len = strlen(taskpath);
	if (path_len < LEN_NAME_MAX) {
		memcpy(sec_d->sub_name, taskpath, path_len);
		sec_d->sub_len = path_len;
	} else {
		memcpy(sec_d->sub_name, taskpath, LEN_NAME_MAX);
		sec_d->sub_len = LEN_NAME_MAX;
	}
	if(is_super_process(taskpath))
		goto pass;

	filename = vfs_get_fullpath((void *)file, TYPE_FILE);
	if (!filename) {
		DEBUG_MSG(HTTC_TSB_INFO, "[%s] get file name error [pass]!\n", __func__);
		goto pass;
	}
	name_len = strlen(filename);
	sec_d->obj_len = (name_len > LEN_NAME_MAX) ? LEN_NAME_MAX : name_len;
	memcpy(sec_d->obj_name, filename, sec_d->obj_len);
	sec_d->start_time = 0;
	sec_d->end_time = 0;
	sec_d->result = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (file->f_mode & FMODE_WRITE) {
		ret = query_whitelist_path(sec_d, 1);
		if(!ret) {
			mask = OPERATE_WRITE;
			ret = -EACCES;
			DEBUG_MSG(HTTC_TSB_INFO, "[%s], sub_name[%s] obj_name[%s] exist in whitelist path\n", __func__, sec_d->sub_name, sec_d->obj_name);
			goto out;
		}
	}

	if (file->f_mode & FMODE_WRITE)
		mask = OPERATE_WRITE;
	else
		mask = OPERATE_READ;

	ret = query_fac_policy_state(sec_d, 1);
	if(ret==CONTROL_READ)
	{
		ret = -EACCES;
		goto out;
	}

	if (ret && (file->f_mode & FMODE_WRITE) /*|| (file->f_mode & FMODE_PWRITE)*/)
		ret = -EACCES;
	else
		ret = 0;

out:
	if (ret == 0) {
		keraudit_log(LOG_CATEGRORY_ACCESS, mask, RESULT_SUCCESS, sec_d, user, current->pid);	//success audit log
		//if (printk_ratelimit())
		DEBUG_MSG(HTTC_TSB_DEBUG, "[%s], comm[%s][%d], parent[%s][%d], [%s][%s]-[%d] SUCCESS\n",
			__func__, current->comm, current->pid, current->parent->comm, current->parent->pid, sec_d->sub_name, sec_d->obj_name, mask);
	} else {
		FileAccessCount_add();
		keraudit_log(LOG_CATEGRORY_ACCESS, mask, RESULT_FAIL, sec_d, user, current->pid);	//fail audit log
		//if (printk_ratelimit())
		DEBUG_MSG(HTTC_TSB_INFO, "[%s], comm[%s][%d], parent[%s][%d], [%s][%s]-[%d] FAIL\n",
			__func__, current->comm, current->pid, current->parent->comm, current->parent->pid, sec_d->sub_name, sec_d->obj_name, mask);
	}

pass:
	if (sec_d)
		kfree(sec_d);
	if (taskpath)
		vfs_put_fullpath(taskpath);
	if (filename)
		vfs_put_fullpath(filename);
	return ret;
}

void update_fac_conf(struct global_control_policy* p_global_policy, int valid_license)
{
#ifdef SANXIA_PLC  //??¨¨y??PLC????D¨¨¨°a¨º1¨®????t¡¤??¨º?????a1?1|?¨¹
	if (g_fac_switch != p_global_policy->be_program_control)
	{
		g_fac_switch = p_global_policy->be_program_control;

		DEBUG_MSG(HTTC_TSB_INFO, "Enter[%s] fac function g_fac_switch[%d] be_program_control[%d]\n", 
			__func__, g_fac_switch, p_global_policy->be_program_control);
	}
#endif
g_fac_switch=valid_license;

DEBUG_MSG(HTTC_TSB_DEBUG, "update fac conf g_fac_switch:%d valid_license:%d\r\n", g_fac_switch, valid_license);
}

void fac_feature_conf_notify_func(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_fac_conf(&global_policy, valid_license);

}
