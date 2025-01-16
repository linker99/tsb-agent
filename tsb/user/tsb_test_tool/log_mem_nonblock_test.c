#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include<string.h>
#include "../tsbapi/tsb_admin.h"

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
	while(1)
	{
		printf("begin read log...............\n");

		int read_len=0, remain_len=0, ret=0;
		char *p=NULL;
		char buff[1024] = {0};
		int buf_len = 1024;
		int hasmore = 0;
		ret = tsb_read_inmem_log_nonblock(buff, &buf_len, &hasmore);
		if (ret)
		{
			printf("read log len=%d hasmore=%d, ret=%d, error!\n", buf_len, hasmore, ret);
			sleep(5);
			continue;
		}
		printf("read log len=%d hasmore=%d, ret=%d\n", buf_len, hasmore, ret);

		remain_len += buf_len;
		p = buff;

		while(remain_len >= sizeof(struct audit_msg))
		{
			struct audit_msg *p_audit_msg = (struct audit_msg *)p;

			if (remain_len < p_audit_msg->total_len)
			{
				printf("remain_len[%d] < total_len[%d]\n", remain_len, p_audit_msg->total_len);
				break;
			}

			printf("type[%d] operate[%d] result[%d] user[%d] pid[%d] sub[%s] obj[%s] total_len[%d]\n", 
				p_audit_msg->type, p_audit_msg->operate, p_audit_msg->result, p_audit_msg->user, p_audit_msg->pid, p_audit_msg->data, 
				p_audit_msg->data+p_audit_msg->len_sub, p_audit_msg->total_len/*, p_audit_msg->sub_hash*/);

			p = p+p_audit_msg->total_len;
			remain_len = remain_len - p_audit_msg->total_len;
		}

		if (remain_len!=0)
			printf("-------------------read error----------------------\n");

		if(hasmore)
		{
			printf("hasmore[%d] have log, continue read\n", hasmore);
			continue;
		}

		printf("hasmore[%d] donot have log, sleep 5s ......\n", hasmore);
		sleep(5);
	}

	return 0;

}