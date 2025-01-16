#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"
#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"


void usage()
{
	printf ("\n"
			" Usage: ./emigrate_keytree [options]\n"
			" options:\n"
			"		 -k <keypath>			- The emigrate key path\n"
			"		 -w <ownerpass>			- The passwd for owner\n"
			"		 -p <passwd>			- The passwd for emigrate key\n"
			"		 -d <authdata>			- The authdata file name\n"
			"		 -e <name>			-Emigrate file name \n"
			"    eg. ./emigrate_keytree -k s://emigrate/a -p 123 -w 123123 -d auth -e emigrate\n"
			"\n");
}

int main(int argc, char** argv){

	int ret = 0;
	int ch = 0;	
	char *key_path = NULL;
	char *file = NULL;
	char *auth = NULL;
	uint8_t *passwd = NULL;
	uint8_t *ownerpass = NULL;
	uint8_t *authdata = NULL;
	uint8_t *obuffer = NULL;
	int  olen_inout = 0;
	unsigned long authlength = 0;
	int authlen = 0;
	
	if (argc < 9){
		usage ();
		return -1;
	}
	
	while((ch = getopt(argc, argv, "w:k:p:d:e:")) != -1){
		switch(ch){
			case 'w':
				ownerpass = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'p':
				passwd = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'd':
				auth = optarg;
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
	if(key_path == NULL || auth == NULL || ownerpass == NULL){
			usage ();
			return -1;
	}
	authdata = httc_util_file_read_full((const char *)auth, &authlength);
	if(authdata == NULL){
		printf("Read fail!\n");
		return -1;
	}
	authlen = authlength;
	ret = tcf_emigrate_keytree((const char *)key_path,passwd,ownerpass,authdata,authlen,&obuffer,&olen_inout);
	if(ret){
		printf("tcf_emigrate_keytree fail!ret:0x%08X(%d)!\n",ret,ret);
		if(obuffer) httc_free(obuffer);
		if(authdata) httc_free(authdata);
		return -1;
	}
	httc_util_dump_hex((const char *)"emigrate",obuffer,olen_inout);
	
	ret =  httc_util_file_write((const char*)file,(const char *)obuffer,olen_inout);
	if(ret != olen_inout){
		printf("Wirte fail!\n");
	}else{
		ret = 0;
	}
	
	if(obuffer) httc_free(obuffer);
	if(authdata) httc_free(authdata);
	
	return ret;
}

