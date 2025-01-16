#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"
#include "mem.h"
#include "file.h"
#include "debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./get_migrate_auth [options]\n"
			" options:\n"
			"		 -n <name>			-Migrate file name \n"
			"    eg. ./get_migrate_auth -n auth\n"
			"\n");
}

int main(int argc, char** argv){


	int ret = 0;
	int ch = 0;
	char *file = NULL;
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
	
	ret = tcs_get_migrate_auth(&authdata,&authlen);
	if(ret){
		printf("tcs_get_migrate_auth fail!ret:0x%08X(%d)!\n",ret,ret);
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

