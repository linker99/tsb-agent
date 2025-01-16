#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../tsbapi/tsb_admin.h"

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	if (strcmp(argv[1], "1") == 0)
		tsb_reload_file_protect_policy();
	//else if (strcmp(argv[1], "2") == 0)
	//	tsb_reload_privilege_process_policy();
	else
		printf("param argv error!\n");
	
	return 0;
}
