#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "httcutils/debug.h"
#include "tcfapi/tcf_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./sign [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The sign key path\n"
			"		 -d <data>			- Data to sign\n"
			"		 -p <passwd>			- The key path password\n"
			"    eg. ./sign -k s://sign/a -d 123456789 -p 123456\n"
			"    eg. ./sign -k s://sign/b -d 123456789 -p 123456\n"
			"\n");
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int ilength = 0;
	char *passwd = NULL;
	char *key_path = NULL;
	char *ibuffer = NULL;
	char sign[64];
	int signlen = 64;

	if (argc != 7){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:p:f:n:i:")) != -1)
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
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
				break;
			default:
				usage();
				break;				
		}
	}

	ret = tcf_sign((unsigned char *)key_path,(unsigned char *)passwd,(unsigned char *)ibuffer, ilength,(unsigned char *)sign,&signlen);
	if(ret){
	
		printf("Error tcf_sign fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}
	httc_util_dump_hex("Sign", sign, signlen);
		
	return 0;	
}




