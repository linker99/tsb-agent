#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"
#include "convert.h"

void usage()
{
	printf ("\n"
			" Usage: ./set_encrypt_key [options]\n"
			" options:\n"
			"		 -k <keypath>			- The key path\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -d <key>			- The key data\n"
			"	 eg. ./set_encrypt_key -k s://a/b -p 123456 -d 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C\n" 		
			"\n");
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int keylength = 0;
    char *keystr = NULL;
	char *passwd = NULL;
	char *keypath = NULL;
	uint8_t key[2*SM4_KEY_SIZE] = {0};	

	if (argc < 6 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:p:d:")) != -1)
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
			case 'd':
				 keystr = optarg;
				 keylength = strlen((const char *)keystr);
				 if(keylength != 4*SM4_KEY_SIZE){
					printf("Error key data!\n");
					usage();
				 	return -1;
				 }
				 httc_util_str2array(key,keystr,keylength);
				break;
			default:
				usage();			
		}

	}
	
	if(passwd == NULL || keypath == NULL || key == NULL){
		usage ();
		return -1;
	}
		
	ret = tcs_set_encrypt_key((unsigned char *)keypath, (unsigned char *)passwd,SM4_KEY_SIZE*2,(unsigned char *)key);
	if(ret){
		printf("Error tcs_set_encrypt_key fail ret:0x%016X!\n",ret);
		return -1;
	}

	return ret;	
}




