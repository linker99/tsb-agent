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
			" Usage: ./get_pubkey [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The sign key path\n"
			"    eg. ./get_pubkey -k s://a/b\n"			
			"\n");
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;	
	char *key_path = NULL;
	char pubkey[64];
	int pubkeylen = 64;

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
				printf ("keypath: %s\n", key_path);
				break;
			default:
				usage();
				break;				
		}
	}
	if(key_path == NULL ){
			usage ();
			return -1;
	}
	ret = tcf_get_public_key((unsigned char *)key_path ,(unsigned char *)pubkey,&pubkeylen);
	if(ret){
	
		printf("tcm_get_public_key fail!\n");
		return -1;
	}
	
	httc_util_dump_hex("Pubkey", pubkey, pubkeylen);
	return 0;	
}



