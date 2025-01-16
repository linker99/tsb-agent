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
	printf ("  Usage: ./set_notice_config [options]\n");
	printf ("  options:\n");
	printf ("         -c <num>        - The notice cache number(default: 1000)\n");
	printf ("     eg: ./set_notice_config\n");
	printf ("     eg: ./set_notice_config -c 2000\n");
	printf ("\n");
}


int main (int argc, char**argv)
{
	int r;
	int ch = 0;
	int num = -1;
	unsigned long datalen = 0;
	const char *file = HTTC_TSS_CONFIG_PATH"notice.version";
	uint64_t *old_version = NULL;
	uint64_t version = 0;
	
	while ((ch = getopt(argc, argv, "c:h")) != -1)
	{
		switch (ch) 
		{
			case 'c':
				num = atoi (optarg);
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

	if ((r = tcf_set_notice_cache_number (num, version))){
		httc_util_pr_error ("tcf_set_notice_cache_number error: %d(0x%x)\n", r, r);
		return -1;
	}
	return 0;
}

