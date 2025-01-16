#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"
#include "httcutils/mem.h"
#include "httcutils/file.h"

void usage()
{
	printf ("\n"
			" Usage: ./decrypt [options]\n"
			" options:\n"
			"		 -k <keypath>			- The cryption key path\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -e <name>			-Encrypt file name \n"
			"    eg. ./decrypt -k s://encrypt/a -p 123456 -e Encrypt\n"
			"    eg. ./decrypt -k s://encrypt/b -p 123456 -e Encrypt\n"
			"\n");
}


int main(int argc, char** argv){
	int ret = 0;
	int ch = 0;
	int mode = 0;	
	char *key_path = NULL;
	char *passwd= NULL;	
	char *file = NULL;
	char obuffer[4096];
	int  olen_inout = 4096;
	unsigned long  decryptlength = 0;
	char *decryptdata = NULL;

	
	if (argc < 5){
		usage ();
		return -1;
	}
	
	while((ch = getopt(argc, argv, "k:p:e:")) != -1){
		switch(ch){
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
				break;
			case 'e':
				file = optarg;
				break;
			default:
				usage();
				break;			
			}
	}
	if(key_path == NULL){
			usage ();
			return -1;
	}
	
	decryptdata = httc_util_file_read_full((const char*)file,&decryptlength);
	if(!decryptdata) return -1;
	
	ret = tcf_decrypt((unsigned char *)key_path,(unsigned char *)passwd, mode,(unsigned char *)decryptdata, decryptlength,(unsigned char *)obuffer,&olen_inout);
	if(ret){
		printf("tcm_encrypt fail!\n");
		if(decryptdata) httc_free(decryptdata);
		return -1;
	}
	printf("tcm_decrypt: %s\n",obuffer);
	
	if(decryptdata) httc_free(decryptdata);
	return ret;
}

