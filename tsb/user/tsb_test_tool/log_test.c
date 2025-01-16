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

int RunCmdGetResult(char* cmd, char* buf, int len)
{
	if(!cmd)
		return -1;

	FILE *fp = popen(cmd,"r");
	fread(buf,len,1,fp);
	pclose(fp);

	return 0;
}

int main(void)

{
	while(1)
	{
		printf("begin read log...............\n");

		char buff[1024]={0};
		RunCmdGetResult("mv /usr/local/httcsec/log/tsb.log /usr/local/httcsec/log/tsb.log_bak", buff, 1024);
		printf("RunCmdGetResult buf:%s\n", buff);

		tsb_rotate_log_file();

		FILE *fp;
		fp=fopen("/usr/local/httcsec/log/tsb.log_bak","rb");
		if (!fp)
		{
			printf("fopen file error! sleep 5s ......\n");
			sleep(5);
			continue;
		}

		int read_len=0, len=0, remain_len=0, data_len=0;
		char *p=NULL;

		memset(buff, 0, sizeof(buff));
		read_len = fread(buff,1,sizeof(buff),fp);
		while(read_len>0)
		{
			remain_len += read_len;
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

			if (remain_len>0)
				memcpy(buff, p, remain_len);

			if (remain_len<0)
				printf("-------------------read error----------------------\n");

			read_len = fread(buff+remain_len, 1, 1024-remain_len, fp);
			printf("read_len[%d] remain_len[%d]\n", read_len, remain_len);
		}
		fclose(fp);

		sleep(5);
	}

	return 0;

}