#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "feature_configure.h"
#include "../utils/debug.h"
#include "../notify/notify.h"
#include "tpcm_def.h"
#include "../msg/command.h"
#include "../sm/sm4.h"
#include "../../include/common.h"
#include "../../include/tcsapi/tcsk_tcm.h"





static struct global_control_policy global_policy;
static uint32_t g_tpcm_feature = 0;
static int g_valid_license = 1;
rwlock_t global_policy_lock;

static DEFINE_MUTEX(tsbinfo_mutex);
static DEFINE_MUTEX(license_config_mutex);
#define NOTICE_WHITELIST_UPDATE 10
void (*global_feature_notify_func[FEATURE_MAX])(void) = {0};

int get_global_feature_conf(struct global_control_policy* p_global_policy, uint32_t* p_tpcm_feature, int* p_valid_license)
{
	read_lock(&global_policy_lock);
	memcpy(p_global_policy, &global_policy, sizeof(global_policy));
	*p_tpcm_feature = g_tpcm_feature;
	*p_valid_license = g_valid_license;
	read_unlock(&global_policy_lock);

	return 0;
}
EXPORT_SYMBOL(get_global_feature_conf);

int register_feature_conf_notify(int type, void *func)
{
	int ret = 0;

	if (type>=FEATURE_MAX)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], type[%d] error\n", __func__, type);
		return -1;
	}
	
	global_feature_notify_func[type] = func;

	return ret;
}
EXPORT_SYMBOL(register_feature_conf_notify);

int unregister_feature_conf_notify(int type, void *func)
{
	int ret = 0;

	if (type>=FEATURE_MAX)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], type[%d] error\n", __func__, type);
		return -1;
	}

	if (global_feature_notify_func[type] != func)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], func address error\n", __func__);
		return -1;
	}
	
	global_feature_notify_func[type] = NULL;

	return ret;
}
EXPORT_SYMBOL(unregister_feature_conf_notify);


void update_conf(void)
{
	int i=0;

	for (i=1; i<FEATURE_MAX; i++)
	{
		if(global_feature_notify_func[i])
			global_feature_notify_func[i]();
	}

	return;
}


int update_global_policy(struct global_control_policy *p_policy_global)
{
	static unsigned int program_control = 0;
	struct notify entry;
	

	write_lock(&global_policy_lock);
	global_policy.be_size = NTOHL(p_policy_global->be_size);
	global_policy.be_boot_measure_on = NTOHL(p_policy_global->be_boot_measure_on);
	global_policy.be_program_measure_on = NTOHL(p_policy_global->be_program_measure_on);
	global_policy.be_dynamic_measure_on = NTOHL(p_policy_global->be_dynamic_measure_on);
	global_policy.be_boot_control = NTOHL(p_policy_global->be_boot_control);
	global_policy.be_program_control = NTOHL(p_policy_global->be_program_control);
	/*
	 * global_policy.be_policy_replay_check = NTOHL(p_policy_global->be_policy_replay_check);
	 * global_policy.be_static_reference_replay_check = NTOHL(p_policy_global->be_static_reference_replay_check);
	 * global_policy.be_dynamic_reference_replay_check = NTOHL(p_policy_global->be_dynamic_reference_replay_check);
	 */

	if( program_control == 0 && global_policy.be_program_control == 1 )
	{	
		int ret;
		memset(&entry, 0, sizeof(struct notify));
		entry.type = NOTICE_WHITELIST_UPDATE; 
		entry.length = 2;
		ret = tsb_put_notify(&entry);
		if(ret != 0)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], put notice to list failed!\n", __func__);
		}
	}

	program_control = global_policy.be_program_control; 
		
	global_policy.be_tsb_flag1 = NTOHL(p_policy_global->be_tsb_flag1);
	global_policy.be_tsb_flag2 = NTOHL(p_policy_global->be_tsb_flag2);
	global_policy.be_tsb_flag3 = NTOHL(p_policy_global->be_tsb_flag3);

	global_policy.be_program_measure_mode = NTOHL(p_policy_global->be_program_measure_mode);
	global_policy.be_measure_use_cache = NTOHL(p_policy_global->be_measure_use_cache);
	global_policy.be_dmeasure_max_busy_delay = NTOHL(p_policy_global->be_dmeasure_max_busy_delay);
	global_policy.be_process_dmeasure_ref_mode = NTOHL(p_policy_global->be_process_dmeasure_ref_mode);
	global_policy.be_process_dmeasure_match_mode = NTOHL(p_policy_global->be_process_dmeasure_match_mode);
	global_policy.be_program_measure_match_mode = NTOHL(p_policy_global->be_program_measure_match_mode);
	global_policy.be_process_dmeasure_lib_mode = NTOHL(p_policy_global->be_process_dmeasure_lib_mode);
	global_policy.be_process_verify_lib_mode = NTOHL(p_policy_global->be_process_verify_lib_mode);

	global_policy.be_process_dmeasure_sub_process_mode = NTOHL(p_policy_global->be_process_dmeasure_sub_process_mode);
	global_policy.be_process_dmeasure_old_process_mode = NTOHL(p_policy_global->be_process_dmeasure_old_process_mode);
	global_policy.be_process_dmeasure_interval = NTOHL(p_policy_global->be_process_dmeasure_interval);
	write_unlock(&global_policy_lock);

	return 0;
}

static long ioctl_reload_global_policy(unsigned long param)
{
	int ret = 0;
	struct global_control_policy policy_global;

	ret = get_global_control_policy(&policy_global);
	if(ret)
	{	
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tcs_get_global_control_policy error ret[%x]!\n", __func__, ret);
		return -1;
	}

	update_global_policy(&policy_global);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], global reload policy success\n", __func__);


	update_conf();

	return 0;
}

static long ioctl_update_global_policy(unsigned long param)
{
	int ret = 0;
	struct global_control_policy policy_global;

	ret =copy_from_user(&policy_global, (void *)param, sizeof(policy_global));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user global update policy failed!\n", __func__);
		return -1;
	}

	update_global_policy(&policy_global);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], global update policy success\n", __func__);

	update_conf();

	return 0;
}

int path_mkdir(const char *parentpath,const char *childpath, umode_t mode)
{
    struct dentry *dentry;
    struct file *dir_file;
    struct path path;
    int dfd,ret;

    dir_file = filp_open(parentpath, O_RDONLY | O_DIRECTORY, 0);
    if (!dir_file) 
    {
        DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], filp_open failed!\n", __func__);
        return PTR_ERR(dir_file);
    }

    dfd = dir_file->f_path.dentry->d_inode->i_sb->s_dev;

    dentry = kern_path_create(dfd, childpath, &path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry))
    {
        DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kern_path_create failed!\n", __func__);
        ret = PTR_ERR(dentry);
        goto out;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
   ret = vfs_mkdir(&init_user_ns,d_inode(path.dentry), dentry, mode);
  
#else
    ret = vfs_mkdir(d_inode(path.dentry), dentry, mode);
#endif
    if(ret)
    {
        path_put(&path);
        DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vfs_mkdir failed!\n", __func__);
        goto out;
    }
    
    done_path_create(&path, dentry);

out:
    filp_close(dir_file, NULL);
    return ret;
}
EXPORT_SYMBOL(path_mkdir);



int policy_linkage_init(void)
{
	int ret = 0;
	struct global_control_policy policy_global = {0};

	rwlock_init(&global_policy_lock);


	/* get tpcm feature */
	ret = get_tpcm_features(&g_tpcm_feature);
	if(ret)
	{	
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_tpcm_features error ret[%x]!\n", __func__, ret);
		goto err_out;
	}



	/* get global policy */
	ret = get_global_control_policy(&policy_global);
	if(ret)
	{	
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_control_policy error ret[%x]!\n", __func__, ret);
		goto err_out;
	}
	update_global_policy(&policy_global);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], global policy init success\n", __func__);

	if (httcsec_io_command_register(COMMAND_UPDATE_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_update_global_policy))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_UPDATE_GLOBAL_POLICY);
		goto err_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_reload_global_policy))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_RELOAD_GLOBAL_POLICY);
		goto reload_global_policy_out;
	}

	update_conf();
	

	return ret;


	httcsec_io_command_unregister(COMMAND_RELOAD_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_reload_global_policy);
reload_global_policy_out:
	httcsec_io_command_unregister(COMMAND_UPDATE_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_update_global_policy);
err_out:
	

	return ret;
}

void policy_linkage_exit(void)
{
	/* other steps */

	httcsec_io_command_unregister(COMMAND_RELOAD_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_reload_global_policy);
	httcsec_io_command_unregister(COMMAND_UPDATE_GLOBAL_POLICY, (httcsec_io_command_func)ioctl_update_global_policy);
  

}
