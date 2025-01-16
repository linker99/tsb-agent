#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int main()
{
	int ret;
	int num = 0;
	int count;
	struct udisk_info *pkg_buf = NULL;

	ret = tsb_udisk_query((struct udisk_info **)&pkg_buf, &num);

	for( count = 0; count < num; count++) 
	{
		printf("NUM:\t\t %d\n", count);
		printf("device:\t\t %s\n", pkg_buf[count].id.dev_name);
		printf("Vendor:\t\t %s\n", pkg_buf[count].id.vender_name);
		printf("serial:\t\t %u\n", pkg_buf[count].id.devno);
		printf("access:\t\t %u", pkg_buf[count].id.access_ctrl);
		printf("\t 0--device invisble, 1--read only, 2--read write\n");
		printf("bMarked:\t %u\n", pkg_buf[count].marked);
		printf("tag:\t\t %s\n", pkg_buf[count].disk_mark.tag);
		printf("guid:\t\t %s\n", pkg_buf[count].disk_mark.guid);
		printf("name:\t\t %s\n", pkg_buf[count].disk_mark.name);
		printf("-------------------------------------------------\n");
	}

	free(pkg_buf);
	return ret;
}
