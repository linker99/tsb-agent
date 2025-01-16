#include "public.h"

static char *program_name;

int usage()
{
	printf("Usage:  %s [COMMAND] [PARAMETER 1] [PARAMETER 2]\n\n", program_name);

	printf("COMMAND:\n");
	printf("        scan               [ time_first / accuracy_first ]  [unzip_ko/ unzip_all / nounzip]  scan whole whitelist, accuracy first is default, and unzip_ko is default\n");
	printf("        reset              [ TCM PASSWROD ]                 reset license\n");
	printf("        set-admin                                           set admin and second-admin\n");
	printf("        set-default-policy global                           set global default policy\n");
	printf("                           dmeasure                         set dmeasure default policy\n");
	printf("                           whitelist                        set whitelist default policy\n");
	printf("                           all                              set above all\n");

	printf("EXAMPLE:\n");
	printf("        %s scan\n", program_name);
	printf("        %s reset\n", program_name);
	printf("        %s set-admin\n", program_name);
	printf("        %s set-default-policy all\n", program_name);
	
 	exit(HT_INIT_HELP);
}

int main(int argc, char **argv)
{
	int ret = HT_INIT_HELP;
	const char *command;

	program_name = argv[0];
	if (argc < 2) {
		return usage();
	}
	command = argv[1];
	
	if (strcmp(command, "scan") == 0) {
		ret = ht_init_command_scan(argc - 2, argv + 2);
		
	} else if (strcmp(command, "reset") == 0) {
		ret = ht_init_command_reset(argc - 2, argv + 2);
		
	} else if (strcmp(command, "set-admin") == 0) {
		ret = ht_init_command_setadmin();
		
	} else if (strcmp(command, "set-default-policy") == 0) {
		ret = ht_init_command_setdefaultpolicy(argc - 2, argv + 2);
		
	}
	
	return ret == HT_INIT_HELP ? usage() : ret;
}
