#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_key.h"
#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "../src/tutils.h"

void usage()
{
	printf ("\n"
			" Usage: ./immigrate_keytree [options]\n"
			" options:\n"
			"		 -k <keypath>			- The immigrate key path\n"
			"		 -e <name>			-Immigrate file name \n"
			"    eg. ./immigrate_keytree -k s://emigrate/a -e emigrate\n"
			"\n");
}

int main(int argc, char** argv){
	
	int ret = 0;
	int ch = 0;	
	char *key_path = NULL;
	char *file = NULL;
	uint8_t *inbuffer = NULL;
	unsigned long buf_len = 0;
	int  inlength  = 0;
	uint32_t source = POLICY_SOURCE_HOST;
	
	if (argc != 5){
		usage ();
		return -1;
	}
	
	while((ch = getopt(argc, argv, "k:e:")) != -1){
		switch(ch){
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'e':
				file = optarg;
				break;
			default:
				usage();
				break;			
			}
	}
	if(key_path == NULL ){
			usage ();
			return -1;
	}

	inbuffer = httc_util_file_read_full((const char*)file,&buf_len);
	if(!inbuffer) return -1;
	
//	httc_util_dump_hex((const char *)"inbuffer",inbuffer,buf_len);
	
	inlength = buf_len;
	
	
	ret = tcf_immigrate_keytree((const char *)key_path,inbuffer,inlength,source);
	if(ret){
		printf("tcf_immigrate_keytree fail! ret:0x%08X(%d)!\n",ret,ret);
		if(inbuffer) httc_free(inbuffer);
		return -1;
	}
	
	if(inbuffer) httc_free(inbuffer);
	return ret;
}

