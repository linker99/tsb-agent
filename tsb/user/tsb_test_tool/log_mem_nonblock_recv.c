#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include<string.h>

#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>
#include <inttypes.h>
#include <time.h>

#include "../tsbapi/tsb_admin.h"

FILE* logFd = NULL;

#define pLog(fmt, ...)	do {									\
	time_t t = time(NULL);						\
struct tm *tm = localtime(&t);					\
	if ((logFd = fopen("tsb.log", "a+")) == NULL) {			\
	fprintf(stdout, "log file open failed");			\
	continue;						\
	}								\
	fprintf(logFd, "%04d-%02d-%02d %02d:%02d:%02d - %s[Line: %d]: ", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, __FILE__, __LINE__);\
	fprintf(logFd, fmt, ##__VA_ARGS__);				\
	fclose(logFd);							\
} while (0)

#define LEN_HASH  32
struct audit_msg {
	unsigned int magic;
	unsigned int type;
	unsigned int operate;
	unsigned int result;
	unsigned int user;
	int pid;
	int repeat_num;
	long time;
	int total_len;
	int len_sub;
	int len_obj;
	char sub_hash[LEN_HASH];
	char data[0];
} __attribute__ ((packed));

int main(void)

{
	pLog("begin read log...............\n");

	while(1)
	{
		int read_len=0, remain_len=0, ret=0;
		char *p=NULL;
		char buff[1024] = {0};
		int buf_len = 1024;
		int hasmore = 0;
		ret = tsb_read_inmem_log_nonblock(buff, &buf_len, &hasmore);
		if (ret)
		{
			pLog("read log len=%d hasmore=%d, ret=%d, error!\n", buf_len, hasmore, ret);
			sleep(5);
			continue;
		}
		//pLog("read log len=%d hasmore=%d, ret=%d\n", buf_len, hasmore, ret);

		remain_len += buf_len;
		p = buff;

		while(remain_len >= sizeof(struct audit_msg))
		{
			struct audit_msg *p_audit_msg = (struct audit_msg *)p;

			if (remain_len < p_audit_msg->total_len)
			{
				pLog("remain_len[%d] < total_len[%d]\n", remain_len, p_audit_msg->total_len);
				break;
			}

			pLog("type[%d] operate[%d] result[%d] user[%d] pid[%d] sub[%s] obj[%s] total_len[%d]\n", 
				p_audit_msg->type, p_audit_msg->operate, p_audit_msg->result, p_audit_msg->user, p_audit_msg->pid, p_audit_msg->data, 
				p_audit_msg->data+p_audit_msg->len_sub, p_audit_msg->total_len/*, p_audit_msg->sub_hash*/);

			p = p+p_audit_msg->total_len;
			remain_len = remain_len - p_audit_msg->total_len;
		}

		if (remain_len!=0)
			pLog("-------------------read error----------------------\n");

		if(hasmore)
		{
			//pLog("hasmore[%d] have log, continue read\n", hasmore);
			continue;
		}

		//pLog("hasmore[%d] donot have log, sleep 5s ......\n", hasmore);
		sleep(5);
	}

	return 0;

}