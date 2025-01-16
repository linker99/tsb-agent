#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "debug.h"
#include "tcs_key.h"
#include "crypto/sm/sm3.h"

#include "file.h"


void usage()
{
	printf ("\n"
			" Usage: ./sign [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The sign key path\n"
			"		 -d <data>			- Data to sign\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -n <filename>			- The name for file to sign\n"
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
	char *signfilename = NULL;
	unsigned long datalength = 0;

	if (argc < 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:p:f:n:i:n:")) != -1)
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
			case 'n':
				signfilename = optarg;
				ibuffer = httc_util_file_read_full((const char *)signfilename,&datalength);
				if(ibuffer == NULL){
					printf("httc_util_file_read_full fail! %s!\n",signfilename);
					return -1;
				}
				ilength = (int)datalength;
				break;
			default:
				usage();
				break;				
		}
	}

	ret = tcs_sign((unsigned char *)key_path,(unsigned char *)passwd,(unsigned char *)ibuffer, ilength,(unsigned char *)sign,&signlen);
	if(ret){
	
		printf("Error tcs_sign fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}
	httc_util_dump_hex("Sign", sign, signlen);
		
	return 0;	
}




