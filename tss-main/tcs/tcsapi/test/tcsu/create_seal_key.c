#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <time.h>


#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./create_seal_key [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The key path\n"
			"		 -t <type>			- Type of key 0:KEY_TYPE_SM2_128 1:KEY_TYPE_SM4_128\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -f <flag>			- The flag of policy\n"
			"		 -n <name>			- The process or role name\n"
			"		 -i <id>			- The group or user id\n"
			"		 -o <operaction>		- 0:tcs_create_sign_key(default) 1:tcs_create_sign_key_on_policy\n"
			"    eg. ./create_seal_key -k s://seal/a -t 0 -p 123456 -o 0\n"
			"    eg. ./create_seal_key -k s://seal/b -t 1 -p 123456 -f 0x28 -n process -o 1\n"
			"\n");
}

static void printf_time(char *str){
	time_t now ;
    struct tm *tm_now ;
    time(&now) ;
    tm_now = localtime(&now) ;//get date
    printf("%s\n",str);
  	printf("datetime: %d-%d-%d %d:%d:%d\n",tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec) ;
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int opt = 0;
	int type = 0;
	uint32_t policy_flags = 0;
	struct auth_policy policy;
    unsigned int user_or_group = 0;
    char *process_or_role = NULL;
	char *passwd = NULL;
	char *keypath = NULL;

	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:t:p:o:f:n:i:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				keypath = optarg;
//				printf ("keypath: %s\n", keypath);
				break;
			case 't':
				type = atoi(optarg);
//				printf ("type: %d\n", type);
				break;
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
				break;
			case 'o':
				opt = atoi(optarg);
//				printf ("opt: %d\n", opt);
				break;
			case 'f':
				policy_flags = strtol (optarg, NULL, 16);
				break;
			case 'n':
				process_or_role = optarg;
				break;
			case 'i':
				 user_or_group = atoi(optarg);
				break;
			default:
				usage();			
			}

	}

	if(opt == 0){
		if(passwd == NULL || keypath == NULL){
			usage ();
			return -1;
		}
		printf_time("tcs_create_seal_key start");
		ret = tcs_create_seal_key((unsigned char *)keypath, type, (unsigned char *)passwd);
		printf_time("tcs_create_seal_key end");
		if(ret){
			printf("Error tcs_create_sign_key fail! ret:0x%016X!\n",ret);
			return -1;
		}
	}else if(opt == 1){
		if(keypath == NULL){
			usage ();
			return -1;
		}
		policy.policy_flags = policy_flags;
		policy.process_or_role = process_or_role;
		policy.user_or_group = user_or_group;
		policy.password = passwd;
		printf_time("tcs_create_seal_key_on_policy start");
		ret = tcs_create_seal_key_on_policy((unsigned char *)keypath, type, &policy);
		printf_time("tcs_create_seal_key_on_policy end");
		if(ret){
			printf("Error tcs_create_sign_key_on_policy fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}

	return ret;	
}

