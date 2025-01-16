#include <linux/highmem.h>

#include "log_config_policy.h"
#include "../version.h"
#include "../utils/klib_fileio.h"
#include "../msg/command.h"
#include "../utils/debug.h"
#include "function_types.h"
#include "tsbapi/tsb_log_notice.h"

static struct log_config log_config_policy;
rwlock_t log_config_lock;

struct exception_log_config{
	struct list_head list;
	char fullpath[256];
	int is_dir;
};
LIST_HEAD(g_list_policy_exception_log);
rwlock_t exception_log_config_lock;

//存在返回0，不存在返回-1
int qurey_exception_log_policy(char *fullpath)
{
	struct list_head *pos = NULL;
	struct exception_log_config *p_policy_exception_log_item = NULL;
	int ret = -1;

	read_lock(&exception_log_config_lock);
	list_for_each(pos, &g_list_policy_exception_log)
	{
		p_policy_exception_log_item = list_entry(pos, struct exception_log_config, list);

		if (p_policy_exception_log_item->is_dir)
		{
			if(strncmp(fullpath, p_policy_exception_log_item->fullpath, strlen(p_policy_exception_log_item->fullpath)) == 0)
			{
				ret = 0;
				break;
			}
		}
		else
		{
			if(strcmp(fullpath, p_policy_exception_log_item->fullpath) == 0)
			{
				ret = 0;
				break;
			}
		}
	}
	read_unlock(&exception_log_config_lock);

	return ret;
}

int get_log_config_policy(int type, int result, struct sec_domain *sec_d)
{
	int ret = 0;
	int aud_r = 0;

	//学习模式/启动度量，日志全审计
	if ((result==RESULT_BYPASS) || (type==TYPE_BMEASURE))
		return 1;

	//白名单日志，有例外日志策略，日志全审计（奔图项目使用）
	if ((type==TYPE_WHITELIST) && (qurey_exception_log_policy(sec_d->obj_name)==0))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], log type[%d] subject[%s] object[%s] is in exception_log.config, all log need write\n", __func__, type, sec_d->sub_name, sec_d->obj_name);
		return 1;
	}

	read_lock(&log_config_lock);
	if (type == TYPE_WHITELIST)
	{
		aud_r = log_config_policy.program_log_level;
	}
	else if (type == TYPE_DMEASURE)
	{
		aud_r = log_config_policy.dmeasure_log_level;
	}
	else if (type == LOG_CATEGRORY_ACCESS)
	{
		aud_r = RECORD_FAIL;
	}
	else if (type == LOG_CATEGRORY_UDISK)
	{
		aud_r = RECORD_ALL;
	}
	else
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], log type[%d] error\n", __func__, type);
		read_unlock(&log_config_lock);
		return ret;
	}
	read_unlock(&log_config_lock);

	switch (aud_r) {
	case RECORD_SUCCESS:
		ret = (result == RESULT_SUCCESS) ? 1 : 0;
		break;
	case RECORD_FAIL:
		ret = (result == RESULT_FAIL) ? 1 : 0;
		break;
	case RECORD_NO:
		ret = 0;
		break;
	case RECORD_ALL:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

int load_log_config(void)
{
	int ret = -1;
	char buff[128] = {0};
	char file_path[128] = {0};
	struct file *file;
	int read_len = 0;
	loff_t offset = 0;

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/log.config");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO,"log_config file open error!\n");
		return ret;
	}
	//if (!file->f_op->read)
	//{
	//	printk("log_config file->f_op->read is null!\n");
	//	goto out;
	//}

	//read_len = klib_fread(buff, 1024, file);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	read_len = kernel_read(file, buff, 128, &offset);
#else
	read_len = kernel_read(file, offset, buff, 128);
#endif
	if (read_len != sizeof(log_config_policy))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kernel_read log_config policy file error!\n", __func__);
		goto out;
	}
	
	write_lock(&log_config_lock);
	memcpy(&log_config_policy, buff, sizeof(log_config_policy));
	write_unlock(&log_config_lock);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], load log_config policy whitelist_log_level[%d] dmeasure_log_level[%d] success\n", 
		__func__, log_config_policy.program_log_level, log_config_policy.dmeasure_log_level);


	ret = 0;
out:
	if(file != NULL)
		filp_close(file, NULL);

	return ret; 
}

static long ioctl_reload_log_config_policy(unsigned long param)
{
	int ret = 0;

	ret = load_log_config();
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], log_config reload policy error!\n", __func__);
		return -1;
	}
	
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], log_config reload policy success\n", __func__);

	return 0;
}

static long ioctl_update_log_config_policy(unsigned long param)
{
	int ret;
	struct log_config lc_policy;

	ret =copy_from_user(&lc_policy, (void *)param, sizeof(lc_policy));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user log_config update policy failed!\n", __func__);
		return -1;
	}

	write_lock(&log_config_lock);
	memcpy(&log_config_policy, &lc_policy, sizeof(lc_policy));
	write_unlock(&log_config_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], log_config update policy whitelist_log_level[%d] dmeasure_log_level[%d] success\n",
		__func__, lc_policy.program_log_level, lc_policy.dmeasure_log_level);

	return 0;
}

void load_exception_log_config(void)
{
#define MAX_LINE_LEN    256
	char buff[MAX_LINE_LEN];
	char file_path[128] = {0};
	struct file *file;
	char *p_src, *p_path/*, *p_hash*/;

	snprintf(file_path, 128, "%s%s", BASE_PATH, "conf/exception_log.config");
	file = filp_open(file_path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], donot have exception_log.config file, don't need control\n", __func__);
		return;
	}

	while(klib_fgets(buff, MAX_LINE_LEN, file))
	{
		struct exception_log_config *p_policy_exception_log_item = NULL;

		p_src=buff;
		p_path = strsep(&p_src, "\n");
		if (!p_path || !*p_path)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], exception_log.config path parse error!\n", __func__);
			goto out;
		}
		//p_hash = strsep(&p_src, "\n");
		//if (!p_hash || !*p_hash)
		//{
		//	DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], exception_log.config hash parse error!\n", __func__);
		//	goto out;
		//}

		p_policy_exception_log_item = kzalloc(sizeof(struct exception_log_config), GFP_KERNEL);
		strncpy(p_policy_exception_log_item->fullpath, p_path, 256);
		p_policy_exception_log_item->is_dir = (*(buff+strlen(buff)-1)=='/') ? 1:0;
		list_add_tail(&p_policy_exception_log_item->list, &g_list_policy_exception_log);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], exception_log.config file path[%s] is_dir[%d]\n", __func__, p_path, p_policy_exception_log_item->is_dir);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], exception_log.config file load success\n", __func__);
out:
	if(file != NULL)
		filp_close(file, NULL);

	return; 
}

int log_config_policy_init(void)
{
	int ret = 0;

	log_config_policy.program_log_level = RECORD_FAIL;
	log_config_policy.dmeasure_log_level = RECORD_FAIL;

	rwlock_init(&log_config_lock);
	ret = load_log_config();
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], load_log_config error!\n", __func__);
		//goto out;
	}

	rwlock_init(&exception_log_config_lock);
	load_exception_log_config();

	ret = httcsec_io_command_register(COMMAND_UPDATE_LOG_CONFIG_POLICY, (httcsec_io_command_func) ioctl_update_log_config_policy);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_UPDATE_LOG_CONFIG_POLICY);
		goto out;
	}

	ret = httcsec_io_command_register(COMMAND_RELOAD_LOG_CONFIG_POLICY, (httcsec_io_command_func) ioctl_reload_log_config_policy);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_RELOAD_LOG_CONFIG_POLICY);
		goto reload_err_out;
	}

	goto out;

reload_err_out:
	httcsec_io_command_unregister(COMMAND_UPDATE_LOG_CONFIG_POLICY, (httcsec_io_command_func) ioctl_update_log_config_policy);
out:
	return ret;
}

void log_config_policy_exit(void)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct exception_log_config *p_policy_exception_log_item = NULL;

	write_lock(&exception_log_config_lock);
	list_for_each_safe(pos, tmp, &g_list_policy_exception_log)
	{
		p_policy_exception_log_item = list_entry(pos, struct exception_log_config, list);
		list_del(pos);
		kfree(p_policy_exception_log_item);
	}
	write_unlock(&exception_log_config_lock);

	httcsec_io_command_unregister(COMMAND_RELOAD_LOG_CONFIG_POLICY, (httcsec_io_command_func) ioctl_reload_log_config_policy);
	httcsec_io_command_unregister(COMMAND_UPDATE_LOG_CONFIG_POLICY, (httcsec_io_command_func) ioctl_update_log_config_policy);
	pr_dev("log_config_policy_exit end.\n");
}
