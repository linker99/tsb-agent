#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "tsbapi/tsb_admin.h"
#include "tcsapi/tcs_policy.h"

int main()
{
	int num;
	int ret;

	num =800;

	ret = tsb_set_notice_cache_number(num);

	return ret;
}

