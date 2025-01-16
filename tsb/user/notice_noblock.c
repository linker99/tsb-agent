#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

#define MISC_DEV "/dev/httcsec"
int fd;
int main()
{
	int length;
	struct notify *pbuf = NULL;
	struct notify *pold = NULL;
	int loop=0;

	fd = tsb_create_notice_read_queue();
	if (fd == -1)
	{
		return fd;
	}

	while(1)
	{
		int ret;
		pbuf = NULL;
		ret = tsb_read_notice_noblock(fd, &pbuf, &length);

		pold = pbuf;
		if (ret == 0)
		{		
			for(loop =0; loop < length ; loop++)
			{
				printf("pid=%d buffer%s length%d ret %d\n",getpid(),pbuf->buf,pbuf->length,length);
				pbuf++;
			}
		}
		else	
			printf("no data receive\n");

		sleep(5);
		free(pold);
		pold = NULL;
	}
	tsb_close_notice_read_queue(fd);
	return 0;
}
