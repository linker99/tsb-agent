#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include "tcfapi/tcf_log_notice.h"
#include "tcsapi/tcs_policy.h"
#include "tcfapi/tcf_log_notice.h"
#include "httcutils/debug.h"

#define MISC_DEV "/dev/httcsec"

int main()
{
	int fd;
	int ret;
	char buffer[100];
	int length;
	struct notify *pbuf = NULL;
	struct notify *pold = NULL;
	int loop=0;

	fd = tcf_create_notice_read_queue();
	if (fd <= 0){
		printf ("tcf_create_notice_read_queue error: %d(0x%x)\n", fd, fd);
	}
	while(1)
	{
		pbuf = NULL;
		ret = tcf_read_notices(fd, &pbuf, &length, 1);

		pold = pbuf;
		if (ret == 0)
		{		
			for(loop =0; loop < length ; loop++)
			{
				printf("pid=%d buffer%s length%d ret %d\n",getpid(),pbuf->buf,pbuf->length,ret);
				httc_util_dump_hex ("notice", pbuf->buf, pbuf->length);
				pbuf++;
			}
		}
		else	
			printf("no data receive\n");

		free(pold);
		pold = NULL;
	}
	tcf_close_notice_read_queue (fd);
	return 0;
}
