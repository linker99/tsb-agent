#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_key.h"
#include "../src/tutils.h"

void usage()
{
	printf ("\n"
			" Usage: ./create_encrypt_key [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The key path\n"
			"		 -t <type>			- Type of key 0:KEY_TYPE_SM2_128 1:KEY_TYPE_SM4_128\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -f <flag>			- The flag of policy\n"
			"		 -n <name>			- The process or role name\n"
			"		 -i <id>			- The group or user id\n"
			"		 -o <operaction>		- 0:create_encrypt_key(default) \n"
			"								  1:tcf_create_inner_encrypt_key \n"
			"								  2:tcf_create_encrypt_key_on_policy\n"
			"								  3:tcf_create_inner_encrypt_key\n"
			"		 eg. ./create_encrypt_key -k s://a/b -t 0 -p 123456 -o 0\n"
			"		 eg. ./create_encrypt_key -k s://a/b -t 1 -p 123456 -f 0x28 -n process -o 2\n"	
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int opt = 0;
	int type = 0;
	uint32_t policy_flags = 0;
	uint32_t source = POLICY_SOURCE_HOST;
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
		ret = tcf_create_encrypt_key((unsigned char *)keypath, type, (unsigned char *)passwd,source);
		if(ret){
			printf("tcm_create_sign_key fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}else if(opt == 1){
		if(passwd == NULL || keypath == NULL){
			usage ();
			return -1;
		}
		ret = tcf_create_inner_encrypt_key((unsigned char *)keypath, type, (unsigned char *)passwd,source);
		if(ret){
			printf("tcm_create_encrypt_key fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}else if(opt == 2){
		if(passwd == NULL ||
		  keypath == NULL ||
		  policy_flags == 0){
			usage ();
			return -1;
		}
		policy.policy_flags = policy_flags;
		policy.process_or_role = process_or_role;
		policy.user_or_group = user_or_group;
		policy.password = passwd;		
		ret = tcf_create_encrypt_key_on_policy((unsigned char *)keypath, type, &policy,source);
		if(ret){
			printf("tcm_create_seal_key fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}else if(opt == 3){
			if(passwd == NULL ||
			  keypath == NULL ||
			  policy_flags == 0){
				usage ();
				return -1;
			}
			policy.policy_flags = policy_flags;
			policy.process_or_role = process_or_role;
			policy.user_or_group = user_or_group;
			policy.password = passwd;		
			ret = tcf_create_inner_encrypt_key_on_policy((unsigned char *)keypath, type, &policy,source);
			if(ret){
				printf("tcm_create_seal_key fail! ret:0x%08X(%d)!\n",ret,ret);
				return -1;
			}
		}

	return ret;	
}



