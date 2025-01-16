#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_store.h"
#include "../src/tutils.h"

void usage()
{
	printf ("\n"
			" Usage: ./nv_define_name_space [options]\n"
			" options:\n"
			"	 	 -s <size>			- The size for nv(defalut:1024)[byte]\n"
			"	 	 -N <name>			- The name for nv\n"
			"		 -w <ownerpasswd>			-The ownerpasswd\n"
			"		 -p <passwd>			- The nv password\n"
			"		 -f <flag>			- The flag of policy\n"
			"		 -n <name>			- The process or role name\n"
			"		 -i <id>			- The group or user id\n"
			"		 -o <operaction>		- 0:tcf_nv_define_space(default) 1:tcf_nv_define_space_on_policy\n"
			"    eg. ./nv_define_name_space -s 4000 -N one -w 123 -p 123456 -o 0\n"
			"    eg. ./nv_define_name_space -s 4000 -N two -w 123 -p 123456 -f 0x28 -n process -o 1\n"
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int opt = 0;
	int size = 1024;
	uint32_t policy_flags = 0;
	struct auth_policy policy;
    unsigned int user_or_group = 0;
    char *process_or_role = NULL;
	char *name = NULL;
	uint8_t *passwd = NULL;
	uint8_t *ownerpasswd = NULL;
	uint32_t source = POLICY_SOURCE_HOST;

	if (argc < 11 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "s:N:w:p:o:f:n:i:")) != -1)
	{
		switch (ch) 
		{
			case 's':
				size = atoi(optarg);
//				printf ("keypath: %s\n", keypath);
				break;
			case 'N':
				name = optarg;
//				printf ("type: %d\n", type);
				break;
			case 'w':
				ownerpasswd = optarg;
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
		if(passwd == NULL || ownerpasswd == NULL){
			usage ();
			return -1;
		}
		ret = tcf_nv_define_named_space((const char *)name, size,ownerpasswd,passwd,source);
		if(ret){
			printf("Error tcf_nv_define_space fail! ret:0x%016X!\n",ret);
			return -1;
		}
	}else if(opt == 1){
		if(passwd == NULL ||
		  ownerpasswd == NULL ||
		  name == NULL ||
		  policy_flags == 0){
			usage ();
			return -1;
		}
		policy.policy_flags = policy_flags;
		policy.process_or_role = process_or_role;
		policy.user_or_group = user_or_group;
		policy.password = passwd;		
		ret = tcf_nv_define_named_space_on_policy((const char *)name,size,ownerpasswd,&policy,source);
		if(ret){
			printf("Error tcf_nv_define_space_on_policy fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}

	return ret;	
}

