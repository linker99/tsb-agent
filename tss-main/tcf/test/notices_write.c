#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "tcfapi/tcf_log_notice.h"
#include "tcsapi/tcs_policy.h"
#include "tcfapi/tcf_log_notice.h"

int main()
{
	int fd;
	int ret = 0;
	char buffer[100];
	int length = 0;
	int count = 0;
	int type;

	while(1)
	{
		memset(buffer, 33+count, 100);
	    type = 10;	
		length = 32;

		ret = tsb_write_notice( buffer, length, type);

		if (ret == 0)
			printf("pid = %d buffer %s length %d count %d \n",getpid(), buffer, length, count);
		sleep(1);
		if(++count > 100)
		{
			count=0;
		}
	}

	return 0;
}

