#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

//#include "httcutils/utils.h"
#include "tcfapi/tcf_key.h"
#include "httcutils/file.h"

void usage()
{
	printf ("\n"
			" Usage: ./get_sealed_data [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -s <filename>			- The name of sealfile\n"
			"    eg. ./get_sealed_data -k s://seal/a -s a.seal\n"
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	uint32_t ilength = 0;	
	char *key_path = NULL;
	char *filename = NULL;
	char obuffer[4096];
	int olen_inout = 4096;
	
	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:s:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 's':
				filename = optarg;
//				printf ("filename: %s\n", filename);
				break;
			default:
				usage();
				break;				
		}
	}

	if( key_path == NULL || filename == NULL){
			usage ();
			return -1;
	}

	ret = tcf_get_sealed_data((unsigned char *)key_path,(unsigned char *)obuffer,&olen_inout,(unsigned char *)filename);
	if(ret){
		printf("tcf_get_sealed_data fail ret:0x%08X!\n",ret);
		return -1;
	}
	ret =  httc_util_file_write((const char*)filename,(const char *)obuffer,olen_inout);
	return 0;
	
}



