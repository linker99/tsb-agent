#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../tsbapi/tsb_admin.h"

//enum {
//	RECORD_SUCCESS = 1,
//	RECORD_FAIL = 2,
//	RECORD_NO = 4,
//	RECORD_ALL = 8,
//};

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	struct log_config log_config_policy;
	log_config_policy.program_log_level = RECORD_FAIL;
	log_config_policy.dmeasure_log_level = RECORD_FAIL;


	if (strcmp(argv[1], "1") == 0)
		tsb_set_log_config(&log_config_policy);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_log_config();
	else
		printf("param argv error!\n");
	
	return 0;
}
