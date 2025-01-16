#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int main(int argc, char **argv)
{
	int ret;
	char *devinfo = NULL;
	struct udisk_mark diskmark;
	char guid[48];

	memset( guid, 0x00, 48 );
	strcpy(guid, "0af70879257db307566d81781d30b8b55bf97a97");
	memset(&diskmark, 0x00, sizeof(struct udisk_mark));

	ret = tsb_udisk_recover(guid, &diskmark);

	return ret;
}
