#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/inotify.h>

#include "tcf.h"
#include "httcutils/mem.h"
#include "httcutils/sys.h"
#include "httcutils/file.h"
#include "httcutils/types.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"
#include "tsbapi/tsb_admin.h"
#include "tcfapi/tcf_error.h"
#include "tcfapi/tcf_bmeasure.h"
#include "tcfapi/tcf_log_notice.h"
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_attest_def.h"
#include "tcsapi/tcs_notice.h"
#include "tcfapi/tcf_attest.h"

#define TSB_LOG_PATH		HTTC_TSB_CONFIG_PATH
#define TSB_LOG_FILE		HTTC_TSB_CONFIG_PATH"tsb.log"
#define TSB_LOG_BAK_FILE	HTTC_TSB_CONFIG_PATH"tsblog.bak"

#define TSB_LOG_OLD_FILE	HTTC_TSB_CONFIG_PATH"tsb.log_*"
#define TSB_LOG_LSEEK_FILE	HTTC_TSB_CONFIG_PATH"tsblog.lseek"


#define LOG_MAGIC 0xCCA1B2DD

struct log_info{
	int size;
	unsigned long end_off;
	struct log item;
};

static int tcf_httc_free_log_items(int num,struct log **logs){

	struct log_info *info = NULL;

	if (!logs)	return TCF_ERR_BAD_DATA;
	while (num--){
		if (logs[num]){
			if (NULL == (info = httc_util_container_of (logs[num], struct log_info, item))){
				httc_util_pr_error ("info of logs[%d] is null\n", num);
				return TCF_ERR_BAD_DATA;
			}
			httc_free (info);
		}
	}

	return 0;
}

int log_util_buffer_to_info (const char *buffer, int size, struct log **logs, int *num_inout, int off)
{
	int ops = 0;
	int num = 0;
	int log_info_len = 0;
	struct log *rlog = NULL;
	struct log *nlog = NULL;
	struct log_info *rinfo = NULL;

	while ((ops < size) && (num < *num_inout))
	{
		if ((ops + sizeof (struct log)) > size){
			httc_util_pr_error ("Invalid log stream(%ld < %d)\n", (long int)(ops + sizeof (struct log)), size);
			*num_inout = num;
			return TCF_ERR_BAD_DATA;
		}

		rlog = (struct log *)(buffer + ops);

		/** Check magic */
		if (LOG_MAGIC != rlog->magic){
			httc_util_pr_error ("Invalid log magic: 0x%08x\n", rlog->magic);
			*num_inout = num;
			return TCF_ERR_BAD_DATA;
		}
		/** Check magic of next log */
		if ((ops + rlog->total_len + sizeof (struct log)) <= size){
			nlog = (struct log *)(buffer + ops + rlog->total_len);
			if (LOG_MAGIC != nlog->magic){
				httc_util_pr_error ("Invalid log stream: Redundant data at end\n");
				*num_inout = num;
				return TCF_ERR_BAD_DATA;
			}
		}

		if (rlog->total_len > (size - ops) || rlog->total_len > 4096){
			httc_util_pr_error ("Invalid log stream\n");
			*num_inout = num;
			return TCF_ERR_BAD_DATA;
		}

		log_info_len = sizeof (struct log_info) + rlog->total_len;
		if (NULL == (rinfo = httc_malloc (log_info_len))){
			httc_util_pr_error ("No mem for log info!\n");
			*num_inout = num;
			return TCF_ERR_NOMEM;
		}
		rinfo->size = log_info_len;
		rinfo->end_off = (off + ops + rlog->total_len);
		memcpy (&rinfo->item, rlog, rlog->total_len);
		*(logs + num) = &rinfo->item;

		num ++;
		ops += rlog->total_len;
	}

	*num_inout = num;
	return TCF_SUCCESS;
}

int log_read (const char *filename, unsigned long offset, struct log **logs, int *num_inout)
{
	int ret = 0;
	char *data = NULL;
	unsigned long rsize = 0;

	if (NULL == (data = httc_util_file_read_offset (TSB_LOG_BAK_FILE, offset, &rsize))){
		httc_util_pr_error ("read tsblog.bak error!\n");
		return TCF_ERR_FILE;
	}

	if (0 != (ret = log_util_buffer_to_info (data, rsize, logs, num_inout, offset))){
		httc_util_pr_error ("change log buffer to info error: %d\n", ret);
		httc_free (data);
		if(*num_inout > 0){
			return TCF_SUCCESS;
		}
		return ret;
	}
	httc_free (data);

	return TCF_SUCCESS;
}

static int dir_lookup (const char *path, char *filename)
{
	DIR *dir = NULL;
	struct dirent *wlDirent = NULL;
	unsigned long psize = 0;

    if (NULL == (dir = opendir (path))) return -1;
    while(1)
    {
        if (NULL == (wlDirent = readdir(dir))) break;
        if (strncmp(wlDirent->d_name,".",1)==0) continue;
        if (wlDirent->d_type == 8)
        {
            sprintf(filename,"%s%s",path,wlDirent->d_name);
            httc_util_pr_dev ("filename: %s\n", filename);
			if (!strstr(filename, "tsb.log_"))	continue;
			if (!httc_util_file_size (filename, &psize) && !psize){
				if (httc_util_rm (filename)){
					httc_util_pr_error ("httc_util_rm %s error!\n", filename);
				}
				continue;
			}
			closedir (dir);
			return 0;
        }
        else if (wlDirent->d_type == 4){
                continue;
        }
    }
    closedir (dir);
    return -1;
}

/*
 * 非阻塞方式读取日志
 */
static int do_read_logs(struct log **rlogs, int num,int *readnum)
{
	int ret = 0;
	unsigned long lseek;
	char *data = NULL;
	unsigned long psize = 0;
	int num_inout_local = num;
	int rotated = 0;
	char filename[MAX_PATH_LENGTH];

	do {
		lseek = 0;
		/** 备份日志文件存在, 从备份文件读取日志 */
		if (!httc_util_file_size (TSB_LOG_BAK_FILE, &psize) && psize){
			if (!httc_util_file_size (TSB_LOG_LSEEK_FILE, &psize) && psize){
				if (psize != sizeof(lseek) ||
					NULL == (data = httc_util_file_read_full (TSB_LOG_LSEEK_FILE, &psize))){
					ret = httc_util_rm (TSB_LOG_LSEEK_FILE);
					if(ret != 0){
						httc_util_pr_error("httc_util_rm %s\n", TSB_LOG_LSEEK_FILE);
						return TCF_ERR_FILE;
					}
					httc_util_pr_error ("read tsblog.lseek error! read from start\n");

				}
				else{
					lseek = *((long*)data);
					httc_free (data);
				}
			}
		}
		else{
			if (httc_util_rm (TSB_LOG_LSEEK_FILE)){
				httc_util_pr_error ("httc_util_rm tsblog.lseek error!\n");
				return TCF_ERR_FILE;
			}
			/** 判断是否读取轮转日志文件 */
			if (!dir_lookup (TSB_LOG_PATH, filename)){
				if (rename(filename, TSB_LOG_BAK_FILE)){
					httc_util_pr_error ("backup %s error!\n", TSB_LOG_FILE);
					return TCF_ERR_FILE;
				}
			}
			else{
				/** 轮转日志输出文件 */
				if (!httc_util_file_size (TSB_LOG_FILE, &psize) && psize){
					if (rename (TSB_LOG_FILE, TSB_LOG_BAK_FILE)){
						httc_util_pr_error ("backup %s error!\n", TSB_LOG_FILE);
						return TCF_ERR_FILE;
					}
					if (0 != (ret = tsb_rotate_log_file ())){
						httc_util_pr_error ("tsb_rotate_log_file error: %d\n", ret);
						return TCF_ERR_TSB;
					}
					rotated = 1;
				}
				else{
					*readnum = 0;
					return TCF_SUCCESS;
				}
			}
		}

		if (0 != (ret = log_read(TSB_LOG_BAK_FILE, lseek, rlogs, &num_inout_local))){
			if (httc_util_rm (TSB_LOG_BAK_FILE,TSB_LOG_LSEEK_FILE)){
				httc_util_pr_error ("httc_util_rm tsblog.lseek tsblog.back error!\n");
				return TCF_ERR_FILE;
			}
			if(rotated){
				return TCF_ERR_FILE;
			}
			else{
				continue;
			}
		}
		*readnum = num_inout_local;
		return TCF_SUCCESS;

	}while(1);

	return TCF_SUCCESS;
}


/** 监听日志文件
	timeout - 超时时间，单位:秒
	成功返回0，失败返回错误码*/
static int select_log (int timeout)
{
    int len;
    int fd, wd;
    int select_ret;
    fd_set read_fds;
	struct timeval tv;
    struct inotify_event event;

    if (access(TSB_LOG_FILE, F_OK) != 0) {
        httc_util_pr_dev("path: %s is not existed\n", TSB_LOG_FILE);
        return -1;
    }

    fd = inotify_init();
    if (fd == -1) {
        httc_util_pr_dev("inotify_init error!\n");
        return -1;
    }
    wd = inotify_add_watch(fd, TSB_LOG_FILE, IN_CREATE | IN_DELETE | IN_MODIFY | IN_DELETE_SELF);
    if (wd < 0) {
        httc_util_pr_dev("inotify_add_watch error\n");
        return -1;
    }

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    select_ret = select(FD_SETSIZE, &read_fds, (fd_set *)0, (fd_set *)0, &tv);
    if (select_ret <= 0) {
		httc_util_pr_dev ("select error: %d\n", select_ret);
        return -1;
    }

    len = read(fd, &event, sizeof(struct inotify_event));
    if (len == (int)sizeof(struct inotify_event)){
        switch (event.mask) {
            case IN_MODIFY:
                httc_util_pr_dev ("modify file: %s\n",event.name);
                return 0;
            default:
                httc_util_pr_dev ("error watch type: %d\n", event.mask);
                return -1;
        }
    }
    return 0;
}

/*
 * 阻塞方式读取日志
 */
int tcf_read_logs (struct log ***logs, int *num_inout, unsigned int timeout)
{
	int r;
	struct log **rlogs = NULL;

	if (NULL == (rlogs = httc_calloc (sizeof(struct log **), *num_inout))){
		httc_util_pr_error ("no mem for rlogs\n");
		return TCF_ERR_NOMEM;
	}

	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_LOG)))
	{
		httc_free (rlogs);
		return r;
	}	

	r = do_read_logs(rlogs,*num_inout,num_inout);
	if(r){
		httc_free (rlogs);
		tcf_util_sem_release (TCF_SEM_INDEX_LOG);
		return r;
	}

	if(*num_inout != 0){
		*logs = rlogs;
		printf ("[tcf_read_logs_noblock] num: %d\n", *num_inout);
		tcf_util_sem_release (TCF_SEM_INDEX_LOG);
		return TCF_SUCCESS;
	}

	r = select_log (timeout);
	if (r){
		httc_free (rlogs);
		tcf_util_sem_release (TCF_SEM_INDEX_LOG);
		return TCF_SUCCESS;
	}else{
		r = do_read_logs(rlogs,*num_inout,num_inout);
		if(!r){
			*logs = rlogs;
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_SUCCESS;
		}
	}

	if (!r && *num_inout){
		printf ("[tcf_read_logs_noblock] num: %d\n", *num_inout);
	}

	tcf_util_sem_release (TCF_SEM_INDEX_LOG);
	return TCF_SUCCESS;
}

int tcf_read_logs_noblock(struct log ***logs, int *num_inout){
	struct log **rlogs = NULL;
	int r;
	if (NULL == (rlogs = httc_calloc (sizeof(struct log **), *num_inout))){
		httc_util_pr_error ("no mem for rlogs\n");
		return TCF_ERR_NOMEM;
	}
	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_LOG)))	
	{
		if(rlogs)
			httc_free (rlogs);
		return r;
	}
	r = do_read_logs(rlogs,*num_inout,num_inout);
	if(!r)
		*logs = rlogs;
	else
		httc_free (rlogs);

	if (!r && *num_inout){
		printf ("[tcf_read_logs_noblock] num: %d\n", *num_inout);
	}
	tcf_util_sem_release (TCF_SEM_INDEX_LOG);
	return r;
}
/*
 * 删除日志
 */
int tcf_remove_logs(struct log *log)
{
	int r = 0;
	unsigned long psize = 0;
	struct log_info *info = NULL;

	if (NULL == (info = httc_util_container_of (log, struct log_info, item))){
		httc_util_pr_error ("null pointer: info(%p)\n", info);
		return TCF_ERR_PARAMETER;
	}

	if ((r = tcf_util_sem_get (TCF_SEM_INDEX_LOG)))	return r;

	if (httc_util_file_size (TSB_LOG_BAK_FILE, &psize) || !psize){
		httc_util_pr_error ("get file(%s) size error!\n", TSB_LOG_BAK_FILE);
		if (httc_util_rm (TSB_LOG_LSEEK_FILE)){
			httc_util_pr_error ("httc_util_rm tsblog.lseek error!\n");
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_FILE;
		}
		tcf_util_sem_release (TCF_SEM_INDEX_LOG);
		return TCF_SUCCESS;
	}
	if (info->end_off < psize){/** 记录日志读取偏移 */
		if (sizeof (info->end_off) != httc_util_file_write (TSB_LOG_LSEEK_FILE, (const char *)(&info->end_off), sizeof (info->end_off))){
			httc_util_pr_error ("write tsblog lseek error\n");
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_FILE;
		}
	}else{
		if (httc_util_rm (TSB_LOG_LSEEK_FILE, TSB_LOG_BAK_FILE)){
			httc_util_pr_error ("httc_util_rm tsblog.lseek  tsblog.bak error!\n");
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_FILE;
		}
	}

	tcf_util_sem_release (TCF_SEM_INDEX_LOG);
	return TCF_SUCCESS;
}

/*
 * 释放读取日志的内存空间
 */
int tcf_free_logs (int num, struct log **logs)
{
	int ret = 0;

	if (!logs)	return TCF_ERR_BAD_DATA;
	if (0 != (ret = tcf_httc_free_log_items (num, logs))){
		httc_util_pr_error ("tcf_httc_free_log_items error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	httc_free (logs);

	return 0;
}

/** 写入日志 */
int tcf_write_logs (const char * data, int length)
{
	int ret = 0;
	if (0 != (ret = write_user_log (data, length))){
		httc_util_pr_error ("write_user_log error: %d(0x%x)\n", ret, ret);
		return TCF_ERR_TSB;
	}
	return TCF_SUCCESS;
}

/*
 * 删除所有日志
 */
int tcf_clear_all_logs()
{
	int ret = 0;
	unsigned long psize = 0;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_LOG)))	return ret;

	/** 轮转日志输出文件 */
	if (!httc_util_file_size (TSB_LOG_FILE, &psize) && psize){
		if (rename (TSB_LOG_FILE, TSB_LOG_BAK_FILE)){
			httc_util_pr_error ("backup %s error!\n", TSB_LOG_FILE);
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_FILE;
		}
		if ((ret = tsb_rotate_log_file ())){
			httc_util_pr_error ("tsb_rotate_log_file error: %d(0x%x)\n", ret, ret);
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_TSB;
		}
		if (httc_util_rm (TSB_LOG_OLD_FILE, TSB_LOG_BAK_FILE, TSB_LOG_LSEEK_FILE)){
			httc_util_pr_error ("httc_util_rm old\\bak\\lseek error!\n");
			tcf_util_sem_release (TCF_SEM_INDEX_LOG);
			return TCF_ERR_FILE;
		}
	}

	tcf_util_sem_release (TCF_SEM_INDEX_LOG);
	return 0;
}


/*
 * 创建通知读取队列
 */
int tcf_create_notice_read_queue (void)
{
	return tsb_create_notice_read_queue ();
}

/*
 * 关闭通知读取队列
 */
void tcf_close_notice_read_queue(int fd)
{
	tsb_close_notice_read_queue (fd);
}

/*
 * 	写入内存通知。
 */
int tcf_write_notices(unsigned char *buffer, int length, int type)
{
	int ret = 0;
	if (0 != (ret = tsb_write_notice (buffer,length,type))){
		if(ret == -1){
			httc_util_pr_error ("tsb_write_notice error: %d(0x%x)\n", ret, ret);
		}
		return TCF_ERR_TSB;
	}
	return TCF_SUCCESS;
}

/*
 * 	阻塞方式读取内存通知。
 */
int tcf_read_notices(int fd, struct notify **ppnode, int *num, unsigned int timeout)
{
	int ret = 0;
	if ((ret = tsb_read_notice (fd, ppnode, num))){
		if(ret == -1){
			httc_util_pr_error ("tsb_read_notice error: %d(0x%x)\n", ret, ret);
		}
		return TCF_ERR_TSB;
	}
	return TCF_SUCCESS;
}

/*
 * 	非阻塞方式读取内存通知。
 */
int tcf_read_notices_noblock(int fd, struct notify **ppnode, int *num)
{
	int ret = 0;
	if ((ret = tsb_read_notice_noblock (fd, ppnode, num))){
		httc_util_pr_error ("tsb_read_notice_noblock error: %d(0x%x)\n", ret, ret);
		return TCF_ERR_TSB;
	}
	return TCF_SUCCESS;
}


