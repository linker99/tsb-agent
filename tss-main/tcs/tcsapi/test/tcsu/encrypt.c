#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"
#include "file.h"
#include "debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./encrypt [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The cryption key path\n"
			"		 -d <data>			- Encrypt and decrypt data\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -e <name>			-Encrypt file name \n"
			"		 -n <name>			-The name for file to decrypt\n"
			"    eg. ./encrypt -k s://encrypt/a -d 123456789 -p 123456 -e Encrypt\n"
			"    eg. ./encrypt -k s://encrypt/b -d 123456789 -p 123456 -e Encrypt\n"
			"\n");
}


int main(int argc, char** argv){
	int ret = 0;
	int ch = 0;
	int mode = 0;
	int ilength = 0;	
	char *key_path = NULL;
	
	char *passwd= NULL;	
	char *ibuffer = NULL;	
	char *file = NULL;
	char obuffer[4096];
	int  olen_inout = 4096;
	char *enfilename = NULL;
	unsigned long datalength = 0;
	
	if (argc < 7){
		usage ();
		return -1;
	}
	
	while((ch = getopt(argc, argv, "k:d:p:e:n:")) != -1){
		switch(ch){
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
			case 'e':
				file = optarg;
				break;
			case 'n':
				enfilename = optarg;
				ibuffer = httc_util_file_read_full((const char *)enfilename,&datalength);
				if(ibuffer == NULL){
					printf("httc_util_file_read_full fail! %s!\n",enfilename);
					return -1;
				}
				ilength = (int)datalength;
				break;
			default:
				usage();
				break;			
			}
		}
	
	if(ibuffer == NULL || file == NULL){
			usage ();
			return -1;
	}
		
	ret = tcs_encrypt((unsigned char *)key_path,(unsigned char *)passwd, mode,(unsigned char *)ibuffer, ilength,(unsigned char *)obuffer,&olen_inout);
	if(ret){
		printf("tcm_encrypt fail! ret:0x%08X!\n",ret);
		return -1;
	}
	
	ret =  httc_util_file_write((const char*)file,(const char *)obuffer,olen_inout);
	if(ret != olen_inout){
		perror("httc_util_file_write");
		return -1;
	}	

	return 0;
}

