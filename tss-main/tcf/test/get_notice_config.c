#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/sys.h>
#include "tcsapi/tcs_error.h"
#include "tcfapi/tcf_config.h"

int main ()
{
	int r;
	int num = 0;

	if ((r = tcf_get_notice_cache_number (&num))){
		httc_util_pr_error ("tcf_get_notice_cache_number error: %d(0x%x)\n", r, r);
		return -1;	
	}
	printf ("notice cache number: %d\n", num);

	return 0;
}

