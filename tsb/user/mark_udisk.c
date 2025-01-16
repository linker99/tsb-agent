#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int generate_guid( char *buf)
{
        int i, a[10];
        char *ptr = NULL;
        srand(time(NULL));

        for( i = 0; i < 10; i++)
        {
                a[i] = rand();
        }

        for( i = 0; i < 5; i++)
        {
                ptr = buf + i*8;
                sprintf(ptr,"%08x",a[i]);
        }
        return 0;
}

int main(int argc, char **argv)
{
	int ret;
	char *devinfo = NULL;
	struct udisk_id id;
	struct udisk_mark diskmark;

	memset(&id, 0x00, sizeof(struct udisk_id));
	memset(&diskmark, 0x00, sizeof(struct udisk_mark));

	id.devno = 3;
	strcpy(diskmark.name, "httc");
	generate_guid(diskmark.guid);
	//strcpy(diskmark.guid,"758fb7a64b1f2f025ef96a3c1b184d9c5b24a219");
	ret = tsb_udisk_mark(&id, &diskmark);

	return ret;
}
