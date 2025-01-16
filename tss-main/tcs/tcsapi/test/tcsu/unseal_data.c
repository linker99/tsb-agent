#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "mem.h"
#include "tcs_key.h"
#include "file.h"

void usage()
{
	printf ("\n"
			" Usage: ./unseal_data [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -f <flag>			- The flag of policy\n"
			"		 -n <name>			- The process or role name\n"
			"		 -i <id>			- The group or user id\n"
			"		 -s <filename>			- The name of sealfile\n"
			"    eg. ./unseal_data -k s://seal/a -p 123456 -s Seal\n"
			"    eg. ./unseal_data -k s://seal/b -p 123456 -f 0x28 -n process -s Seal\n"
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	unsigned long ilength = 0;
	char *passwd = NULL;
	char *key_path = NULL;
	char *filename = NULL;
	char *ibuffer = NULL;
	char unsealbuffer[4096];
	int unseallength = 4096;

	if (argc != 7 ){
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
			    ibuffer = httc_util_file_read_full((const char *) filename, &ilength);
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

	ret = tcs_unseal_data((unsigned char *)key_path,(unsigned char *)ibuffer, (int)ilength,(unsigned char *)unsealbuffer,&unseallength,(unsigned char *)passwd);
	if(ret){
		printf("tcs_unseal_data fail! ret:0x%08X!\n",ret);
		if(ibuffer) httc_free(ibuffer);
		return -1;
	}
	if(ibuffer) httc_free(ibuffer);
	printf("unseal data %s\n",unsealbuffer);	

	return 0;
	
}



