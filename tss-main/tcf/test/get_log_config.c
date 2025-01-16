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
	struct log_config config;

	if ((r = tcf_get_log_config (&config))){
		httc_util_pr_error ("tcf_get_log_config error: %d(0x%x)\n", r, r);
		return -1;	
	}

	printf ("log config:\n");
	printf ("  config.program_log_level: %d\n", config.program_log_level);
	printf ("  config.dmeasure_log_level: %d\n", config.dmeasure_log_level);
	printf ("  config.log_buffer_on: %d\n", config.log_buffer_on);
	printf ("  config.log_integrity_on: %d\n", config.log_integrity_on);
	printf ("  config.log_buffer_limit: %d\n", config.log_buffer_limit);
	printf ("  config.log_buffer_rotate_size: %d\n", config.log_buffer_rotate_size);
	printf ("  config.log_buffer_rotate_time: %d\n", config.log_buffer_rotate_time);
	printf ("  config.log_inmem_limit: %d\n", config.log_inmem_limit);

	return 0;
}

