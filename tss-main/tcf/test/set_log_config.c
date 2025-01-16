#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

#include <httcutils/mem.h>
#include <httcutils/debug.h>
#include <httcutils/file.h>
#include "tcfapi/tcf_config.h"
#include "tcsapi/tcs_constant.h"

void usage()
{
	printf ("\n");
	printf ("  Usage: ./set_log_config [options]\n");
	printf ("  options:\n");
	printf ("         -t <type>        - The type of setting item\n");
	printf ("         					 0 - program_log_level (default:0)\n");
	printf ("         					 1 - dmeasure_log_level (default:0)\n");
	printf ("         					 2 - log_buffer_on (default:1)\n");
	printf ("         					 3 - log_integrity_on (default:0)\n");
	printf ("         					 4 - log_buffer_limit (default:1024)\n");
	printf ("         					 5 - log_buffer_rotate_size (default:1024)\n");
	printf ("         					 6 - log_buffer_rotate_time (default:24)\n");
	printf ("         					 7 - log_inmem_limit (default:1024)\n");
	printf ("         -v <value>       - The value of setting item\n");
	printf ("     eg: ./set_log_config\n");
	printf ("     eg: ./set_log_config -t 1 -v 0\n");
	printf ("\n");
}

struct log_config config = {
	.program_log_level = 0,
	.dmeasure_log_level = 0,
	.log_buffer_on = 1,
	.log_integrity_on = 0,
	.log_buffer_limit = 1024,
	.log_buffer_rotate_size = 1024,
	.log_buffer_rotate_time = 24,
	.log_inmem_limit = 1024
};

int main (int argc, char**argv)
{
	int r;
	int ch = 0;
	int type = -1;
	int value = -1;
	unsigned long datalen = 0;
	const char *file = HTTC_TSS_CONFIG_PATH"log.version";
	uint64_t *old_version = NULL;
	uint64_t version = 0;
	
	while ((ch = getopt(argc, argv, "t:v:h")) != -1)
	{
		switch (ch) 
		{
			case 't':
				type = atoi (optarg);
				break;
			case 'v':
				value = atoi (optarg);
				break;	
			default:
				usage ();
				break;
		}
	}

	old_version = httc_util_file_read_full(file, &datalen);
	if(old_version == NULL){
		version = 1;
	}else{
		version = *old_version + 1;
	}
	if(old_version) httc_free(old_version);

	if ((type>=0) && (value>=0)){
		if ((r = tcf_get_log_config (&config))){
			httc_util_pr_error ("tcf_get_log_config error: %d(0x%x)\n", r, r);
		}
		*((uint32_t *)&config + type) = value;
	}
	if ((r = tcf_set_log_config (&config, version))){
		httc_util_pr_error ("tcf_set_log_config error: %d(0x%x)\n", r, r);
		return -1;
	}
	return 0;
}

