#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../tsbapi/tsb_admin.h"

int main(int argc, char **argv)
{

	struct log_config log_config_policy;
	log_config_policy.program_log_level = 2;
	log_config_policy.dmeasure_log_level = 2;

	FILE* fp_w = fopen("log_config", "wb");
	fwrite(&log_config_policy, 1, sizeof(log_config_policy), fp_w);
	fclose(fp_w);
	
	return 0;
}