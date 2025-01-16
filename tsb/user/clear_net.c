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
	ret = tsb_clear_filter_list();
	return ret;
}
