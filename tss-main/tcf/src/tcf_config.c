#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <httcutils/sys.h>
#include <httcutils/mem.h>
#include <httcutils/debug.h>
#include <httcutils/convert.h>
#include <httcutils/file.h>
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_attest.h"
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_notice.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcf.h"
#include "tutils.h"

#define TCF_LOG_FILE			HTTC_TSS_CONFIG_PATH"log.config"
#define TCF_NOTICE_FILE			HTTC_TSS_CONFIG_PATH"notice.config"
#define TCF_LOG_VERSION_PATH 	HTTC_TSS_CONFIG_PATH"log.version"
#define TCF_NOTICE_VERSION_PATH	HTTC_TSS_CONFIG_PATH"notice.version"

static struct log_config config_default = {
	.program_log_level = RECORD_FAIL,
	.dmeasure_log_level = RECORD_FAIL,
	.log_buffer_on = 0,
	.log_integrity_on = 0,
	.log_buffer_limit = 0,
	.log_buffer_rotate_size = 0,
	.log_buffer_rotate_time = 0,
	.log_inmem_limit = 0,
};

/*
 * 	设置日志配置
 */
int tcf_set_log_config (const struct log_config *config, uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	unsigned long datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_LOG_FILE)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_LOG_VERSION_PATH,&datalen);

	if(old_version && datalen == sizeof(uint64_t)){
		if(*old_version >= version){
			httc_util_pr_error("Version error! old:0x%016lX, new: 0x%016lX\n",(long unsigned int)*old_version,(long unsigned int)version);
			if(old_version) httc_free(old_version);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_VERSION;
		}
	}else if(old_version && datalen != sizeof(uint64_t)){
			httc_util_pr_error("Version file error! version:0x%016lX, length:%ld\n",(long unsigned int)*old_version,(long unsigned int)datalen);
			if(old_version) httc_free(old_version);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
	}
	if(old_version) httc_free(old_version);

	ret = httc_util_file_write (TCF_LOG_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}

	ret = httc_util_file_write (TCF_LOG_FILE, (const char*)config, sizeof (struct log_config));
	if (ret != sizeof (struct log_config)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof (struct log_config));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (0 != (ret = tsb_set_log_config (config))){
		httc_util_pr_info ("tsb_set_log_config : %d(0x%x)\n", ret, ret);
	}

	httc_write_version_notices (version, POLICY_TYPE_LOG);
	return 0;
}

/*
 * 	读取日志配置
 */
int tcf_get_log_config(struct log_config *config)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_LOG_FILE, &size))){
		httc_util_pr_dev ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		memcpy (config, &config_default, sizeof (struct log_config));
		return 0;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (struct log_config)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	memcpy (config, data, sizeof (struct log_config));
	if (data) httc_free (data);
	return 0;
}

/*
 * 	设置通知缓存条数
 */
int tcf_set_notice_cache_number(int num, uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	unsigned long datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_NOTICE_FILE)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_NOTICE_VERSION_PATH,&datalen);
	if(old_version && datalen == sizeof(uint64_t)){
		if(*old_version >= version){
			httc_util_pr_error("Version error! old:0x%016lX, new: 0x%016lX\n",(long unsigned int)*old_version,(long unsigned int)version);
			if(old_version) httc_free(old_version);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_VERSION;
		}
	}else if(old_version && datalen != sizeof(uint64_t)){
			httc_util_pr_error("Version file error! version:0x%016lX, length:%ld\n",(long unsigned int)*old_version,(long unsigned int)datalen);
			if(old_version) httc_free(old_version);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
	}
	if(old_version) httc_free(old_version);

	ret = httc_util_file_write (TCF_NOTICE_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}

	ret = httc_util_file_write (TCF_NOTICE_FILE, (const char*)&num, sizeof (num));
	if (ret != sizeof (num)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof (num));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (0 != (ret = tsb_set_notice_cache_number (num))){
		httc_util_pr_info ("tsb_set_notice_cache_number : %d(0x%x)\n", ret, ret);
	}

	httc_write_version_notices (version, POLICY_TYPE_NOTICE);
	return 0;
}

/*
 * 	读取通知缓存条数
 */
int tcf_get_notice_cache_number(int *num)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_NOTICE_FILE, &size))){
		httc_util_pr_error ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_ITEM_NOT_FOUND;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (*num)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	*num = *(int*)data;
	if (data) httc_free (data);
	return 0;
}

