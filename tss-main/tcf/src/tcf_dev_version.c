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

#define TCF_FILE_VERSION_PATH 	HTTC_TSS_CONFIG_PATH"file.version"
#define TCF_CDROM_VERSION_PATH 	HTTC_TSS_CONFIG_PATH"cdrom.version"
#define TCF_UDISK_VERSION_PATH 	HTTC_TSS_CONFIG_PATH"udisk.version"
#define TCF_NETWORK_VERSION_PATH 	HTTC_TSS_CONFIG_PATH"network.version"
/*
 * 	设置file protect 版本号
 */
int tcf_set_file_protect_version(uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	uint64_t datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_FILE_VERSION_PATH)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_FILE_VERSION_PATH,(unsigned long *)&datalen);

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

	ret = httc_util_file_write (TCF_FILE_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}


	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	/*no need notify tsb*/

	//httc_write_version_notices (version, POLICY_TYPE_FILE_PROTECT);

	return TCF_SUCCESS;
}

/*
 * 	获取file protect 版本号
 */
int tcf_get_file_protect_config(uint64_t *get_version)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_FILE_VERSION_PATH, (unsigned long *)&size))){
		httc_util_pr_dev ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		*get_version=0;
		return 0;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (uint64_t)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	memcpy (get_version, data, sizeof (uint64_t));
	if (data) httc_free (data);
	return 0;
}


/*
 * 	设置cdrom版本号
 */
int tcf_set_cdrom_version(uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	uint64_t datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_CDROM_VERSION_PATH)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_CDROM_VERSION_PATH,(unsigned long *)&datalen);

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

	ret = httc_util_file_write (TCF_CDROM_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}


	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	/*no need notify tsb*/

	//httc_write_version_notices (version, POLICY_TYPE_DEV_PROTECT);

	return TCF_SUCCESS;
}

/*
 * 	获取cdrom版本号
 */
int tcf_get_cdrom_config(uint64_t *get_version)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_CDROM_VERSION_PATH, (unsigned long *)&size))){
		httc_util_pr_dev ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		*get_version=0;
		return 0;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (uint64_t)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	memcpy (get_version, data, sizeof (uint64_t));
	if (data) httc_free (data);
	return 0;
}


/*
 * 	设置udisk版本号
 */
int tcf_set_udisk_version(uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	uint64_t datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_UDISK_VERSION_PATH)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_UDISK_VERSION_PATH,(unsigned long *)&datalen);

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

	ret = httc_util_file_write (TCF_UDISK_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}


	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	/*no need notify tsb*/

	//httc_write_version_notices (version, POLICY_TYPE_UDISK_PROTECT);

	return TCF_SUCCESS;
}

/*
 * 	获取udisk版本号
 */
int tcf_get_udisk_config(uint64_t *get_version)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_UDISK_VERSION_PATH, (unsigned long *)&size))){
		httc_util_pr_dev ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		*get_version=0;
		return 0;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (uint64_t)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	memcpy (get_version, data, sizeof (uint64_t));
	if (data) httc_free (data);
	return 0;
}


/*
 * 	设置网络控制版本号
 */
int tcf_set_network_version(uint64_t version)
{
	int ret = 0;
	uint64_t *old_version = NULL;
	uint64_t datalen = 0;

	if (httc_util_create_path_of_fullpath (TCF_NETWORK_VERSION_PATH)){
		httc_util_pr_error ("Create log path error!\n");
		return TCF_ERR_FILE;
	}

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	old_version =  httc_util_file_read_full(TCF_NETWORK_VERSION_PATH,(unsigned long *)&datalen);

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

	ret = httc_util_file_write (TCF_NETWORK_VERSION_PATH, (const char *)&version, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)){
		httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(uint64_t));
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		return TCF_ERR_FILE;
	}


	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	/*no need notify tsb*/

//	httc_write_version_notices (version, POLICY_TYPE_UDISK_PROTECT);

	return TCF_SUCCESS;
}

/*
 * 	获取网络控制版本号
 */
int tcf_get_network_config(uint64_t *get_version)
{
	int ret;
	unsigned long size = 0;
	char *data = NULL;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;
	if (NULL == (data = httc_util_file_read_full (TCF_NETWORK_VERSION_PATH, (unsigned long *)&size))){
		httc_util_pr_dev ("httc_util_file_read_full error\n");
		tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
		*get_version=0;
		return 0;
	}
	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);

	if (size != sizeof (uint64_t)){
		httc_util_pr_error ("Invalid param\n");
		if (data) httc_free (data);
		return TCF_ERR_BAD_DATA;
	}
	memcpy (get_version, data, sizeof (uint64_t));
	if (data) httc_free (data);
	return 0;
}