#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"
#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./get_migrate_auth [options]\n"
			" options:\n"
			"		 -n <name>			-Migrate file name \n"
			"    eg. ./get_migrate_auth -k s://emigrate/a -p 123 -n auth\n"
			"\n");
}

int main(int argc, char** argv){


	int ret = 0;
	int ch = 0;
	char *key_path = NULL;
	char *file = NULL;
	uint8_t *passwd = NULL;
	uint8_t *authdata = NULL;
	int authlen = 0;
	
	if (argc < 3){
		usage ();
		return -1;
	}
	
	while((ch = getopt(argc, argv, "n:")) != -1){
		switch(ch){
			case 'n':
				file = optarg;
				break;
			default:
				usage();
				break;			
			}
	}
	if(file == NULL){
			usage ();
			return -1;
	}
	
	ret = tcf_get_migrate_auth(&authdata,&authlen);
	if(ret){
		printf("tcf_get_migrate_auth fail!ret:0x%08X(%d)!\n",ret,ret);
		if(authdata) httc_free(authdata);
		return -1;
	}
	httc_util_dump_hex((const char *)"authdata",authdata,authlen);
	ret =  httc_util_file_write((const char*)file,(const char *)authdata,authlen);
	if(ret != authlen){
		printf("Wirte fail!\n");
	}
	
	if(authdata) httc_free(authdata);
	ret = 0;
	return ret;
}

