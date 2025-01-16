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
			" Usage: ./unseal_stored_data [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -s <filename>			- The name of sealfile\n"
			"    eg. ./unseal_stored_data -k s://seal/a -p 123456 -s Seal\n"
			"    eg. ./unseal_stored_data -k s://seal/b -p 123456 -s Seal\n"
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	uint32_t ilength = 0;	
	char *passwd = NULL;
	char *key_path = NULL;
	char *filename = NULL;
	char *ibuffer = NULL;
	char unsealbuffer[4096];
	int unseallength = 4096;


	if(argc != 7){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:p:s:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
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

	ret = tcf_unseal_stored_data((unsigned char *)key_path,(unsigned char *)unsealbuffer, &unseallength,(unsigned char *)filename,(unsigned char *)passwd);
	if(ret){
		printf("tcf_unseal_stored_data fail! ret:0x%08X!\n",ret);
		return -1;
	}
	printf("unseal stored_data %s\n",unsealbuffer);	

	return 0;	
}



