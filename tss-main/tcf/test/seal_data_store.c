#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "../src/tutils.h"
#include "tcfapi/tcf_key.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./seal_data_store [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -d <data>			- Data to be encapsulated or unsealed\n"
			"		 -f <filename>			- The file want to seal\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -s <filename>			- The name of sealfile\n"
			"    eg. ./seal_data_store -k s://seal/a -d 123456789 -p 123456 -s Seal\n"
			"    eg. ./seal_data_store -k s://seal/b -d 123456789 -p 123456 -s Seal\n"
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int ilength = 0;	
	int olen_inout = 4096;
	char *passwd = NULL;	
	char *key_path = NULL;
	char *filename = NULL;
	char *ibuffer = NULL;
	char obuffer[4096];
	uint32_t source = POLICY_SOURCE_HOST;
	char *sealfile = NULL;
	unsigned long datalen = 0;

	if (argc < 9 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:f:p:s:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'd':
				ibuffer = optarg;
				ilength = strlen((const char*)ibuffer);
//				printf ("ibuffer: %s\n", ibuffer);
				break;
			case 'f':
				sealfile = optarg;
				ibuffer = httc_util_file_read_full((const char *)sealfile, &datalen);
				if(ibuffer == NULL){
					printf("httc_util_file_read_full fail! %s!\n",sealfile);
					usage ();
					return -1;
				}
				ilength = datalen;
//				printf ("ibuffer: %s\n", ibuffer);
				break;
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
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

	if(passwd == NULL || key_path == NULL || filename == NULL){
			usage ();
			return -1;
	}
	
	ret = tcf_seal_data_store((unsigned char *)key_path,(unsigned char *)ibuffer, ilength,(unsigned char *)filename,(unsigned char *)passwd,source);
	if(ret){
		printf("tcf_seal_data_store fail! ret:0x%08X!\n",ret);
		return -1;
	}
	
	return 0;
	
}



