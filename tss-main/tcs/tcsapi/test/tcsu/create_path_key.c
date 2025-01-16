#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./create_path_key [options]\n"
			" options:\n"
			"    -k <keypath>           - The key path\n"
			"    -t <type>              - Type of key 0:KEY_TYPE_SM2_128 1:KEY_TYPE_SM4_128\n"
			"    -o <operaction>        - 0:tcs_create_path_key(default)  1:tcs_create_migratable_path_key\n"
			"    eg. ./create_path_key -k s://path/a -t 0 -o 0\n"
			"    eg. ./create_path_key -k s://path/a/b -t 1 -o 1\n"
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int opt = 0;
	int type = 0;
	char *keypath = NULL;

	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:t:o:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				keypath = optarg;
				printf ("keypath: %s\n", keypath);
				break;
			case 't':
				type = atoi(optarg);
				printf ("type: %d\n", type);
				break;
			case 'o':
				opt = atoi(optarg);
				printf ("opt: %d\n", opt);
				break;				
			default:
				usage();			
			}

	}
	
	if(opt == 0){
		if( keypath == NULL){
			usage ();
			return -1;
		}
		ret = tcs_create_path_key((unsigned char *)keypath, type);
		if(ret){
			printf("Error tcm_create_sign_key fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}else if(opt == 1){
		if(keypath == NULL){
			usage ();
			return -1;
		}
		ret = tcs_create_migratable_path_key((unsigned char *)keypath, type);
		if(ret){
			printf("Error tcs_create_migratable_path_key fail! ret:0x%08X(%d)!\n",ret,ret);
			return -1;
		}
	}

	return ret;	
}


