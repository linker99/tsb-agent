#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int main()
{
	
	char buffer[100];
	int count = 0;

	while(1)
	{
		int ret;
		int length=32;
		int type = 10;
		memset(buffer, 32+count, 100);
		ret = tsb_write_notice( buffer, length, type);

		if (ret == 0)
			printf("pid = %d buffer %s length %d count %d \n",getpid(), buffer, length, count);
		sleep(1);

		if(++count >= 94)
		{
			count = 0;
		}
	}

	return 0;
}

