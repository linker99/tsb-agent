#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int main()
{
	int ret = 0;
	int count = 20;

	ret = tsb_set_process_protect();
	while(1)
	{
		printf("pid = %d  \n",getpid());
		sleep(1);
		count--;
		if (count == 0)
			break;
	}
	ret = tsb_set_unprocess_protect();
	
	while(1)
	{
		printf("pid = %d  \n",getpid());
		sleep(1);
	}
	return 0;
}

