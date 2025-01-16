#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ioctl.h"
#include "tsbapi/tsb_admin.h"
#include "tsbapi/tsb_measure_user.h"

#define MAX_COMMAND_NR 256
enum{
	COMMAND_SWITCH_LOG_FILE  = 0x1,
	COMMAND_UPDATE_GLOBAL_POLICY,
	COMMAND_RELOAD_GLOBAL_POLICY,
	COMMAND_ADD_WHITELIST_POLICY,
	COMMAND_DELETE_WHITELIST_POLICY,
	COMMAND_RELOAD_WHITELIST_POLICY,
	COMMAND_UPDATE_DMEASURE_POLICY,
	COMMAND_RELOAD_DMEASURE_POLICY,
	COMMAND_UPDATE_PROCESS_ID_POLICY,
	COMMAND_RELOAD_PROCESS_ID_POLICY,
	COMMAND_UPDATE_PROCESS_ROLE_POLICY,
	COMMAND_RELOAD_PROCESS_ROLE_POLICY,
	COMMAND_UPDATE_LOG_CONFIG_POLICY,
	COMMAND_RELOAD_LOG_CONFIG_POLICY,
	COMMAND_SET_PROCESS_IDS_POLICY,
	COMMAND_RELOAD_PROCESS_IDS_POLICY,
	COMMAND_SET_PROCESS_ROLES_POLICY,
	COMMAND_RELOAD_PROCESS_ROLES_POLICY,

	COMMAND_ADD_DMEASURE_PROCESS_POLICY,
	COMMAND_DELETE_DMEASURE_PROCESS_POLICY,
	COMMAND_RELOAD_DMEASURE_PROCESS_POLICY,

	COMMAND_SET_PTRACE_POLICY,
	COMMAND_RELOAD_PTRACE_POLICY,

	COMMAND_GET_NOTIFY_INFO_BLOCK,
	COMMAND_GET_NOTIFY_INFO_NOBLOCK,
	COMMAND_SEND_NOTIFY_PKG,
	COMMAND_CREATE_NOTIFY_QUEUE,
	COMMAND_SET_NOTIFY_QUEUE_NUM,
	COMMAND_PROCESS_PROTECT_REQ,
	COMMAND_PROCESS_UNPROTECT_REQ,

        COMMAND_CDROM_RELOAD,
        COMMAND_UDISK_QUERY,
        COMMAND_UDISK_MARK,
        COMMAND_UDISK_RELOAD,
	COMMAND_UDISK_RECOVER,
	COMMAND_NET_CONF_CLEAR,
	COMMAND_NET_CONF_RELOAD,

	COMMAND_RELOAD_CRITICAL_CONFILE_POLICY,

	COMMAND_WRITE_USER_LOG,

	COMMAND_READ_MEM_LOG,
	COMMAND_READ_MEM_LOG_NONBLOCK,

	COMMAND_RELOAD_FILE_PROTECT_POLICY,
	/* COMMAND_RELOAD_PRIVILEGE_PROCESS_POLICY, */

	COMMAND_ADD_FAC_WHITELIST_PATH_POLICY,
	COMMAND_DELETE_FAC_WHITELIST_PATH_POLICY,
	COMMAND_RELOAD_FAC_WHITELIST_PATH_POLICY,

	COMMAND_WRITE_USER_INFO_LOG,

	COMMAND_WHITELIST_USER_INTERFACE = 100,
	COMMAND_DMEASURE_USER_INTERFACE,
	COMMAND_PROCESS_IDENTITY_USER_INTERFACE,
	COMMAND_WRITE_TSB_LICENSE,
	COMMAND_READ_TSB_LICENSE,
	COMMAND_WRITE_TSB_NV_CONFIG,
    COMMAND_READ_TSB_NV_CONFIG,

//#ifdef _CHECK_SCRIPT
	COMMAND_ADD_BLACKLIST_POLICY,
	COMMAND_DEL_BLACKLIST_POLICY,
	COMMAND_RELOAD_BLACKLIST_POLICY,
	COMMAND_SYNC_BLACKLIST_TO_FILE,
//#endif	
	COMMAND_SET_TRUST_SCORE,
    COMMAND_SET_LOG_MODE,
	COMMAND_GET_LOG_MODE,
	COMMAND_MAX = MAX_COMMAND_NR
};

#define MISC_NAME "httcsec"

#define HTTCSEC_MISC_DEVICE_TYPE  0xAF

#define SWITCH_LOG_FILE        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SWITCH_LOG_FILE, unsigned long)

#define TEST_ADD_WHITELIST        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_ADD_WHITELIST_POLICY, unsigned long)
#define TEST_DEL_WHITELIST        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_DELETE_WHITELIST_POLICY, unsigned long)
#define TEST_REL_WHITELIST        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_WHITELIST_POLICY, unsigned long)

#define UPDATE_DMEASURE_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_UPDATE_DMEASURE_POLICY, unsigned long)
#define RELOAD_DMEASURE_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_DMEASURE_POLICY, unsigned long)

#define UPDATE_GLOBAL_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_UPDATE_GLOBAL_POLICY, unsigned long)
#define RELOAD_GLOBAL_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_GLOBAL_POLICY, unsigned long)

#define UPDATE_LOG_CONFIG_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_UPDATE_LOG_CONFIG_POLICY, unsigned long)
#define RELOAD_LOG_CONFIG_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_LOG_CONFIG_POLICY, unsigned long)

#define SET_PROCESS_IDS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SET_PROCESS_IDS_POLICY, unsigned long)
#define RELOAD_PROCESS_IDS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_PROCESS_IDS_POLICY, unsigned long)
#define SET_PROCESS_ROLES_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SET_PROCESS_ROLES_POLICY, unsigned long)
#define RELOAD_PROCESS_ROLES_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_PROCESS_ROLES_POLICY, unsigned long)

#define ADD_DMEASURE_PROCESS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_ADD_DMEASURE_PROCESS_POLICY, unsigned long)
#define DELETE_DMEASURE_PROCESS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_DELETE_DMEASURE_PROCESS_POLICY, unsigned long)
#define RELOAD_DMEASURE_PROCESS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_DMEASURE_PROCESS_POLICY, unsigned long)

#define SET_PTRACE_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SET_PTRACE_POLICY, unsigned long)
#define RELOAD_PTRACE_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_PTRACE_POLICY, unsigned long)


#define WHITELIST_USER_INTERFACE        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_WHITELIST_USER_INTERFACE, unsigned long)
#define DMEASURE_USER_INTERFACE        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_DMEASURE_USER_INTERFACE, unsigned long)
#define PROCESS_IDENTITY_USER_INTERFACE        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_PROCESS_IDENTITY_USER_INTERFACE, unsigned long)

#define GET_NOTIFY_INFO_BLOCK        	  _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_GET_NOTIFY_INFO_BLOCK, unsigned long)
#define GET_NOTIFY_INFO_NOBLOCK        	  _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_GET_NOTIFY_INFO_NOBLOCK, unsigned long)

#define SEND_NOTIFY_PKG                _IOWR (HTTCSEC_MISC_DEVICE_TYPE, COMMAND_SEND_NOTIFY_PKG, unsigned long)
#define CREATE_NOTIFY_QUEUE                _IOWR (HTTCSEC_MISC_DEVICE_TYPE, COMMAND_CREATE_NOTIFY_QUEUE, unsigned long)
#define SET_NOTIFY_QUEUE_NUM                _IOWR (HTTCSEC_MISC_DEVICE_TYPE, COMMAND_SET_NOTIFY_QUEUE_NUM, unsigned long)

#define PROCESS_PROTECT_REQ            _IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_PROCESS_PROTECT_REQ, unsigned long)
#define PROCESS_UNPROTECT_REQ            _IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_PROCESS_UNPROTECT_REQ, unsigned long)

#define CDROM_RELOAD		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_CDROM_RELOAD, unsigned long)
#define UDISK_QUERY		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_UDISK_QUERY, unsigned long)
#define UDISK_MARK		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_UDISK_MARK, unsigned long)
#define UDISK_RELOAD		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_UDISK_RELOAD, unsigned long)
#define UDISK_RECOVER		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_UDISK_RECOVER, unsigned long)

#define NET_CONF_RELOAD		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_NET_CONF_RELOAD, unsigned long)
#define NET_CONF_CLEAR		_IOWR (HTTCSEC_MISC_DEVICE_TYPE,COMMAND_NET_CONF_CLEAR, unsigned long)

#define RELOAD_CRITICAL_CONFILE_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_CRITICAL_CONFILE_POLICY, unsigned long)

#define WRITE_USER_LOG        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_WRITE_USER_LOG, unsigned long)

#define READ_MEM_LOG        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_READ_MEM_LOG, unsigned long)
#define READ_MEM_LOG_NONBLOCK        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_READ_MEM_LOG_NONBLOCK, unsigned long)

#define RELOAD_FILE_PROTECT_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_FILE_PROTECT_POLICY, unsigned long)
//#define RELOAD_PRIVILEGE_PROCESS_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_PRIVILEGE_PROCESS_POLICY, unsigned long)


#define ADD_FAC_WHITELIST_PATH_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_ADD_FAC_WHITELIST_PATH_POLICY, unsigned long)
#define DELETE_FAC_WHITELIST_PATH_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_DELETE_FAC_WHITELIST_PATH_POLICY, unsigned long)
#define RELOAD_FAC_WHITELIST_PATH_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_FAC_WHITELIST_PATH_POLICY, unsigned long)

#define WRITE_USER_INFO_LOG        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_WRITE_USER_INFO_LOG, unsigned long)
#define WRITE_TSB_LICENSE          _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_WRITE_TSB_LICENSE, unsigned long)
#define READ_TSB_LICENSE           _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_READ_TSB_LICENSE, unsigned long)
#define WRITE_TSB_NV_CONFIG        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_WRITE_TSB_NV_CONFIG, unsigned long)
#define READ_TSB_NV_CONFIG         _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_READ_TSB_NV_CONFIG, unsigned long)

//#ifdef _CHECK_SCRIPT
#define ADD_BLACKLIST_POLICY        _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_ADD_BLACKLIST_POLICY, unsigned long)
#define DEL_BLACKLIST_POLICY        	_IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_DEL_BLACKLIST_POLICY, unsigned long)
#define RELOAD_BLACKLIST_POLICY	_IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_RELOAD_BLACKLIST_POLICY, unsigned long)
#define SYNC_BLACKLIST_TO_FILE        	_IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SYNC_BLACKLIST_TO_FILE, unsigned long)
//#endif

#define SET_TRUST_SCORE _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SET_TRUST_SCORE, unsigned long)
#define SET_LOG_MODE _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_SET_LOG_MODE, unsigned long)
#define GET_LOG_MODE _IOWR (HTTCSEC_MISC_DEVICE_TYPE,  COMMAND_GET_LOG_MODE, unsigned long)


/* whitelist user interface type */
enum{
	TYPE_WHITELIST_MEASURE_FILE  = 1,
	TYPE_WHITELIST_MEASURE_FILE_PATH,
	TYPE_WHITELIST_MATCH_FILE,
	TYPE_WHITELIST_MATCH_FILE_PATH,
};

/* dmesure user interface type */
enum{
	TYPE_DMEASURE_KERNEL_MEMORY  = 1,
	TYPE_DMEASURE_KERNEL_MEMORY_ALL,
	TYPE_DMEASURE_PROCESS,
};

/* process identity user interface type */
enum{
	TYPE_PROCESS_IDENTITY_VERIFY  = 1,
	TYPE_PROCESS_IDENTITY_GET,
	TYPE_PROCESS_IDENTITY_ROLE,
};

struct tsb_general_policy
{
	int length;
	const char *data;
};

struct tsb_user_interface_parameter
{
	int type;
	int length;
	char *data;
};

struct tsb_user_read_memory_log_parameter
{
	int  *hasmore;
	int  *length;
	char *data;
};


struct tsb_user_set_log_level
{
	int type;
};

int tsb_reload_cdrom_config(void)
{
	int ret = 0;
	ret = httcsec_ioctl(CDROM_RELOAD, (unsigned long)&ret);
	return ret;
}

int tsb_reload_network(void)
{
	int ret = 0;
	ret = httcsec_ioctl( NET_CONF_RELOAD, (unsigned long)&ret);
	return ret;
}

int  tsb_clear_filter_list(void)
{
	int ret = 0;
	ret = httcsec_ioctl( NET_CONF_CLEAR, (unsigned long)&ret);
	return ret;
}

int tsb_udisk_query(struct udisk_info **diskinfo, int *num)
{
	int ret;
	unsigned char *buffer = NULL;

	posix_memalign((void **)&buffer,4096,8192);
	if (buffer == NULL)
	{
		printf("OOM.\n");
		return -1;
	}

	memset(buffer,0x00,8192);

	ret = httcsec_ioctl( UDISK_QUERY, (unsigned long)buffer );
	if(ret<0)
		return ret;

	*num = ret;
	*diskinfo = (struct udisk_info *)buffer;

	return 0;
}

int tsb_udisk_mark(struct udisk_id *id, struct udisk_mark *disk_mark)
{
	int ret;
	struct udisk_info pkg_buf; 

	memset(&pkg_buf, 0x00, sizeof(struct udisk_info));
	memcpy(&pkg_buf.id, id, sizeof(struct udisk_id));
	memcpy(&pkg_buf.disk_mark, disk_mark, sizeof(struct udisk_mark));

	ret = httcsec_ioctl( UDISK_MARK, (unsigned long)&pkg_buf );

	return ret;
}

int tsb_udisk_recover(char *guid, struct udisk_mark *disk_mark)
{
	int ret;
	struct udisk_recover pkg_buf; 

	memset(&pkg_buf, 0x00, sizeof(struct udisk_recover));
	strcpy( pkg_buf.guid, guid );
	memcpy(&pkg_buf.disk_mark, disk_mark, sizeof(struct udisk_mark));

	ret = httcsec_ioctl( UDISK_RECOVER, (unsigned long)&pkg_buf );

	return ret;
}

int tsb_reload_udisk_config( void )
{
	int ret;
	ret = httcsec_ioctl( UDISK_RELOAD, (unsigned long)&ret );
	return ret;
}

//int ioctl_send_recv_kernel(unsigned int cmd, const char *buffer)
//{
//	int fd;
//	int ret = 0;
//
//	fd = open("/dev/"MISC_NAME, O_RDWR, 0);
//	if (fd < 0) 
//	{
//		printf("Failed to open/dev/%s\n", MISC_NAME);
//		return -1;
//	}
//
//	printf("_IOC_TYPE(cmd)[0x%x].\n", _IOC_TYPE(cmd)); //TEST_CMD��һ�����
//	printf("_IOC_NR(cmd)[0x%x].\n", _IOC_NR(cmd));     //TEST_CMD�ڶ������
//
//	ret = ioctl(fd, cmd, buffer);
//	//if (ret) 
//	//{
//	//	printf("ioctl return error! ret[%d]\n", ret);
//	//}
//
//	close(fd);
//	return ret;
//}

int notice_ioctl(int fd, unsigned long cmd,unsigned long param)
{
	int r = 0;
	if ((r =  ioctl(fd, cmd, param)) < 0)
	{
		pr_dev("notice_ioctl cmd %lu ,param %lu failed,%s\n",cmd,param,strerror(errno));
		return -1;
	}
	return r;
}

int tsb_create_notice_read_queue()
{
	int r = 0;
	int fd;
	unsigned long param = 0;

	fd = open(MISC_DEV, O_RDWR);
	if (fd < 0)
	{
		printf("Failed to open %s\n", MISC_NAME);
		return -100;
	}

	r = notice_ioctl(fd, CREATE_NOTIFY_QUEUE, param);
	if ( r < 0)
	{
		close(fd);
		printf("create read queue failed\n");
		return -1;
	}
	return fd;
}

void tsb_close_notice_read_queue(int fd)
{
	close(fd);
}

int tsb_write_notice( unsigned char *buffer, int length, int type )
{
	int ret;
	struct notify notify_buffer;
	
	if( length > MAX_NOTICE_SIZE || length < 0)
	{
		printf("length is invalid  %d\n", length);
		return -1;
	}

        memset(&notify_buffer, 0, sizeof(struct notify));

	notify_buffer.length = length;
	notify_buffer.type   = type;

	if( buffer != NULL && length != 0 )
		memcpy(notify_buffer.buf, buffer, length);

	ret =  httcsec_ioctl( SEND_NOTIFY_PKG, (unsigned long)&notify_buffer);
	//if( ret != 0)
	//{
	//	printf("pid = %d set notice failed %d\n",getpid(),ret);
	//}

	return ret;
}

int tsb_set_process_protect(void)
{
        int ret;
        int num;
        ret =  httcsec_ioctl(PROCESS_PROTECT_REQ, (unsigned long)&num);
        return ret;
}

int tsb_set_unprocess_protect(void)
{
        int ret;
        int num;
        ret =  httcsec_ioctl(PROCESS_UNPROTECT_REQ, (unsigned long)&num);
        return ret;
}

int tsb_set_notice_cache_number(int num)
{
	int ret;

	if( num > 1000 || num < 100)
	{
		printf("set notice cache range [100 ~ 1000] \n");
		return -1;
	}
	
	ret =  httcsec_ioctl( SET_NOTIFY_QUEUE_NUM, (unsigned long)&num);
	//if( ret != 0)
	//{
	//	printf("set notice cache failed %d\n",ret);
	//}

	return ret;
}

int tsb_read_notice(int fd, struct notify **ppnode, int *num)
{
	int ret;
	unsigned char *buffer = NULL;

	posix_memalign((void **)&buffer,4096,81920);
	if (buffer == NULL) 
	{
		printf("OOM.\n");
		return -1;
	}

	ret =  notice_ioctl(fd, GET_NOTIFY_INFO_BLOCK, (unsigned long)buffer);
	if( ret < 0)
	{
		printf("pid = %d get notice failed %d\n",getpid(),ret);
		free(buffer);
		return ret;
	}

	*num = ret;
	*ppnode = (struct notify*)buffer;
	return 0;
}

int tsb_read_notice_noblock(int fd, struct notify **ppnode, int *num)
{
	int ret;
	unsigned char *buffer = NULL;

	posix_memalign((void **)&buffer,4096,81920);
	if (buffer == NULL) 
	{
		printf("OOM.\n");
		return -1;
	}

	ret =  notice_ioctl(fd, GET_NOTIFY_INFO_NOBLOCK, (unsigned long)buffer);
	if( ret < 0)
	{
		printf("pid = %d get notice failed %d\n",getpid(),ret);
		free(buffer);
		return ret;
	}

	*num =  ret;
	*ppnode = (struct notify*)buffer; 
	return 0;
}

int tsb_rotate_log_file()
{
	char buffer[100] = "switch log file";
	return httcsec_ioctl(SWITCH_LOG_FILE, (unsigned long)buffer);
}

int tsb_add_file_integrity(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(TEST_ADD_WHITELIST, (unsigned long)&general_policy);
}

int tsb_remove_file_integrity(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(TEST_DEL_WHITELIST, (unsigned long)&general_policy);
}

int tsb_reload_file_integrity()
{
	char buffer[100] = "whitelist reload";
	return httcsec_ioctl(TEST_REL_WHITELIST, (unsigned long)buffer);
}

int tsb_set_dmeasure_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(UPDATE_DMEASURE_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_dmeasure_policy()
{
	char buffer[100] = "dmeasure reload";
	return httcsec_ioctl(RELOAD_DMEASURE_POLICY, (unsigned long)buffer);
}

int tsb_set_global_control_policy(const char *data ,int length)
{

	return httcsec_ioctl(UPDATE_GLOBAL_POLICY, (unsigned long)data);
	
}

int tsb_reload_global_control_policy()
{
	char buffer[100] = "global reload";
	return httcsec_ioctl(RELOAD_GLOBAL_POLICY, (unsigned long)buffer);
}

int tsb_set_log_config(const struct log_config *config)
{
	return httcsec_ioctl(UPDATE_LOG_CONFIG_POLICY, (unsigned long)config);
}

int tsb_reload_log_config()
{
	char buffer[100] = "log_config reload";
	return httcsec_ioctl(RELOAD_LOG_CONFIG_POLICY, (unsigned long)buffer);
}

int tsb_set_process_ids(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(SET_PROCESS_IDS_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_process_ids()
{
	char buffer[100] = "process_ids reload";
	return httcsec_ioctl(RELOAD_PROCESS_IDS_POLICY, (unsigned long)buffer);
}

int tsb_set_process_roles(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(SET_PROCESS_ROLES_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_process_roles()
{
	char buffer[100] = "process_roles reload";
	return httcsec_ioctl(RELOAD_PROCESS_ROLES_POLICY, (unsigned long)buffer);
}

int tsb_add_process_dmeasure_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(ADD_DMEASURE_PROCESS_POLICY, (unsigned long)&general_policy);
}

int tsb_remove_process_dmeasure_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(DELETE_DMEASURE_PROCESS_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_process_dmeasure_policy()
{
	char buffer[100] = "dmeasure process reload";
	return httcsec_ioctl(RELOAD_DMEASURE_PROCESS_POLICY, (unsigned long)buffer);
}

int tsb_set_ptrace_process_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(SET_PTRACE_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_ptrace_process_policy()
{
	char buffer[100] = "ptrace reload";
	return httcsec_ioctl(RELOAD_PTRACE_POLICY, (unsigned long)buffer);
}

int tsb_reload_critical_confile_integrity()
{
	char buffer[100] = "critical_confile reload";
	return httcsec_ioctl(RELOAD_CRITICAL_CONFILE_POLICY, (unsigned long)buffer);
}

int write_user_log(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(WRITE_USER_LOG, (unsigned long)&general_policy);
}

int write_user_info_log(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(WRITE_USER_INFO_LOG, (unsigned long)&general_policy);
}

int tsb_read_inmem_log(unsigned char *buffer,int *length_inout,int *hasmore)
{
	int ret = 0;
	struct tsb_user_read_memory_log_parameter parameter = {0};

	parameter.hasmore = hasmore;
	parameter.length = length_inout;
	parameter.data = (char *)buffer;

	ret = httcsec_ioctl(READ_MEM_LOG, (unsigned long)&parameter);

	return ret;
}

int tsb_read_inmem_log_nonblock(unsigned char *buffer,int *length_inout,int *hasmore)
{
	int ret = 0;
	struct tsb_user_read_memory_log_parameter parameter = {0};

	parameter.hasmore = hasmore;
	parameter.length = length_inout;
	parameter.data = (char *)buffer;

	ret = httcsec_ioctl(READ_MEM_LOG_NONBLOCK, (unsigned long)&parameter);

	return ret;
}

int tsb_reload_file_protect_policy()
{
	char buffer[100] = "file_protect reload";
	return httcsec_ioctl(RELOAD_FILE_PROTECT_POLICY, (unsigned long)buffer);
}

//int tsb_reload_privilege_process_policy()
//{
//	char buffer[100] = "privilege_process reload";
//	return httcsec_ioctl(RELOAD_PRIVILEGE_PROCESS_POLICY, (unsigned long)buffer);
//}

int tsb_add_fac_whitelist_path_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(ADD_FAC_WHITELIST_PATH_POLICY, (unsigned long)&general_policy);
}

int tsb_remove_fac_whitelist_path_policy(const char *data ,int length)
{
	struct tsb_general_policy general_policy;
	general_policy.length = length;
	general_policy.data = data;

	return httcsec_ioctl(DELETE_FAC_WHITELIST_PATH_POLICY, (unsigned long)&general_policy);
}

int tsb_reload_fac_whitelist_path_policy()
{
	char buffer[100] = "fac whitelist policy reload";
	return httcsec_ioctl(RELOAD_FAC_WHITELIST_PATH_POLICY, (unsigned long)buffer);
}



/* user interface */
int tsb_measure_file(const char *path)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_WHITELIST_MEASURE_FILE;
	parameter.length = strlen(path)+1;
	parameter.data = (char *)path;

	ret = httcsec_ioctl(WHITELIST_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_measure_file_path(const char *path)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_WHITELIST_MEASURE_FILE_PATH;
	parameter.length = strlen(path)+1;
	parameter.data = (char *)path;

	ret = httcsec_ioctl(WHITELIST_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}


int tsb_match_file_integrity(const unsigned char *hash, int hash_length)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_WHITELIST_MATCH_FILE;
	parameter.length = hash_length;
	parameter.data = (char *)hash;

	ret = httcsec_ioctl(WHITELIST_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_match_file_integrity_by_path(
		const unsigned char *hash, int hash_length,
		const unsigned char *path, int path_length)
{
	int ret = 0;
	int len = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_WHITELIST_MATCH_FILE_PATH;
	parameter.length = sizeof(hash_length)+hash_length+sizeof(path_length)+path_length;
	parameter.data = malloc(parameter.length);
	memset(parameter.data, 0, parameter.length);

	memcpy(parameter.data, &hash_length, sizeof(hash_length));
	len = sizeof(hash_length);
	memcpy(parameter.data+len, hash, hash_length);
	len += hash_length;
	memcpy(parameter.data+len, &path_length, sizeof(path_length));
	len += sizeof(path_length);
	memcpy(parameter.data+len, path, path_length);

	ret = httcsec_ioctl(WHITELIST_USER_INTERFACE, (unsigned long)&parameter);

	free(parameter.data);

	return ret;
}

int tsb_measure_kernel_memory(const char *name)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_DMEASURE_KERNEL_MEMORY;
	parameter.length = strlen(name)+1;
	parameter.data = (char *)name;

	ret = httcsec_ioctl(DMEASURE_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_measure_kernel_memory_all()
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_DMEASURE_KERNEL_MEMORY_ALL;

	ret = httcsec_ioctl(DMEASURE_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_measure_process(unsigned pid)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_DMEASURE_PROCESS;
	parameter.length = sizeof(pid);
	parameter.data =  (char *)&pid;

	ret = httcsec_ioctl(DMEASURE_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_verify_process(int pid,const char *name)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_PROCESS_IDENTITY_VERIFY;
	parameter.length = sizeof(pid) + strlen(name) + 1;
	parameter.data = malloc(parameter.length);
	memcpy(parameter.data, &pid, sizeof(pid));
	memcpy(parameter.data+sizeof(pid), name, strlen(name)+1);

	ret = httcsec_ioctl(PROCESS_IDENTITY_USER_INTERFACE, (unsigned long)&parameter);

	free(parameter.data);

	return ret;
}


int tsb_get_process_identity(unsigned char *process_name,int *process_name_length)
{
	int ret = 0;
	char name[512] = {0};
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_PROCESS_IDENTITY_GET;
	parameter.length = 512;
	parameter.data = name;

	ret = httcsec_ioctl(PROCESS_IDENTITY_USER_INTERFACE, (unsigned long)&parameter);
	if (!ret)
	{
		memcpy(process_name, name, strlen(name)+1);
		*process_name_length = strlen(name)+1;
	}

	return ret;
}


int tsb_is_role_member(const unsigned char *role_name)
{
	int ret = 0;
	struct tsb_user_interface_parameter parameter = {0};

	parameter.type = TYPE_PROCESS_IDENTITY_ROLE;
	parameter.length = strlen(role_name)+1;
	parameter.data = (char *)role_name;

	ret = httcsec_ioctl(PROCESS_IDENTITY_USER_INTERFACE, (unsigned long)&parameter);

	return ret;
}

int tsb_write_license(unsigned int uiDataLen, const char *pcData)
{
    int ret=PARAM_ERR;
    struct tsb_user_interface_parameter parameter = {0};
    
    if((0 == uiDataLen) || (NULL == pcData))
    {
    	printf("%s param err\n",__func__);
    	return ret;
    }
    
    parameter.length = uiDataLen;
    parameter.data = (char *)pcData;
    ret = httcsec_ioctl(WRITE_TSB_LICENSE, (unsigned long)&parameter);
    return ret;
}

int tsb_read_license(char *pcData,int *puiDataLen)
{
    int ret=PARAM_ERR;
    struct tsb_user_license parameter = {0};
    
    if((NULL == puiDataLen) || (NULL == pcData))
    {
    	printf("%s param err\n",__func__);
    	return ret;
    }
    
    parameter.puiDataLen = puiDataLen;
    parameter.pcData = pcData;
    ret = httcsec_ioctl(READ_TSB_LICENSE, (unsigned long)&parameter);
    return ret;
}

int tsb_write_nv_config(uint32_t index, int length,unsigned char *data, unsigned char *usepasswd)
{
    int ret=PARAM_ERR;
    struct tsb_write_nv_parameter parameter = {0};
    
    if((0 == length) || (NULL == data) || (NULL == usepasswd))
    {
        printf("%s param err\n",__func__);
        return ret;
    }
    
    if(strncmp(usepasswd,TSB_USERPASS,strlen(TSB_USERPASS)))
    {
        ret = USERPASS_ERR;
        printf("%s line is %d,userpass is %s, param err\n",__func__,__LINE__,usepasswd);
        return ret;
    }
    
    parameter.index = index;
    parameter.length = length;
    parameter.data = data;
    ret = httcsec_ioctl(WRITE_TSB_NV_CONFIG, (unsigned long)&parameter);
    return ret;
}

int tsb_read_nv_config(uint32_t index, int length,unsigned char *data, unsigned char *usepasswd)
{
    int ret=PARAM_ERR;
    struct tsb_read_nv_parameter parameter = {0};
    
    if((NULL == data) || (NULL == usepasswd))
    {
        printf("%s line is %d,param err\n",__func__,__LINE__);
        return ret;
    }
    
    if(strncmp(usepasswd,TSB_USERPASS,strlen(TSB_USERPASS)))
    {
        ret = USERPASS_ERR;
        printf("%s line is %d,userpass is %s, param err\n",__func__,__LINE__,usepasswd);
    	return ret;
    }
    
    parameter.index = index;
    parameter.length = length;
    parameter.data = data;
    ret = httcsec_ioctl(READ_TSB_NV_CONFIG, (unsigned long)&parameter);
    return ret;
}

//blacklist

int tsb_add_blcaklist_policy(unsigned char *data,int length)
{
    int ret;
    common_header p_header = { 0 };

    p_header.length = length;
    p_header.data = data;

    //send to kernel
   ret = httcsec_ioctl(ADD_BLACKLIST_POLICY, (unsigned long)&p_header);

    return ret;
}

int tsb_remove_blacklist_policy(unsigned char *data,int length) 
{
    int ret;
    common_header p_header = { 0 };

    p_header.length = length;
    p_header.data = data;


    //send to kernel
    ret = httcsec_ioctl(DEL_BLACKLIST_POLICY, (unsigned long)&p_header);


    return ret;

}

int tsb_reload_policy_by_file() 
{
    int ret = 0;
    ret = httcsec_ioctl(RELOAD_BLACKLIST_POLICY, (unsigned long)&ret);
    return ret;

}

int tsb_sync_list_to_file() 
{
    int ret = 0;
    ret = httcsec_ioctl(SYNC_BLACKLIST_TO_FILE, (unsigned long)&ret);
    return ret;
}

int tsb_set_trust_score(uint32_t  trust_score)
{
	int ret=0;
	ret = httcsec_ioctl(SET_TRUST_SCORE, (unsigned long)&trust_score);
    return ret;

}

 // ����ֵ�������óɹ����0�����ɹ���������Ӧ�������Զ�
 int tsb_set_log_mode(int mode)
 {
	int ret;
	struct tsb_user_set_log_level parameter = {0}; 
	parameter.type=mode;
	ret = httcsec_ioctl(SET_LOG_MODE, (unsigned long)&parameter);
	return ret;
 }

 // ����ֵ��ֵ����mode�� ��ֵ�����������Զ���

 int tsb_get_log_mode()
 {
 	int ret;
    struct tsb_user_set_log_level parameter = {0};
    ret = httcsec_ioctl(GET_LOG_MODE, (unsigned long)&parameter);
	 if(!ret)
	{
		ret=parameter.type;;
	}
    return ret;

 }        
