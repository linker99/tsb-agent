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
	ret = tsb_reload_udisk_config();
	return ret;
}
