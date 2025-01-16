#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"
#include "httcutils/debug.h"
#include "httcutils/convert.h"


int tcf_get_encrypt_key(
		unsigned char *key_path, unsigned char *passwd,
		int *length, unsigned char *key);



void usage()
{
	printf ("\n"
			" Usage: ./get_encrypt_key [options]\n"
			" options:\n"
			"		 -k <keypath>			- The key path\n"
			"		 -p <passwd>			- The key path password\n"
			"	 eg. ./get_encrypt_key -k s://a/b -p 123456\n" 		
			"\n");
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int keylength = SM4_KEY_SIZE;
	char *passwd = NULL;
	char *keypath = NULL;
	uint8_t key[SM4_KEY_SIZE] = {0};

	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:p:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				keypath = optarg;
//				printf ("keypath: %s\n", keypath);
				break;
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
				break;
			default:
				usage();			
		}

	}
	
	if(passwd == NULL || keypath == NULL){
		usage ();
		return -1;
	}
	ret = tcf_get_encrypt_key((unsigned char *)keypath, (unsigned char *)passwd,&keylength,(unsigned char *)key);
	if(ret){
		printf("Error tcf_get_encrypt_key fail ret:0x%016X!\n",ret);
		return -1;
	}
	httc_util_dump_hex((const char *)"key", key, keylength);
	return ret;	
}

