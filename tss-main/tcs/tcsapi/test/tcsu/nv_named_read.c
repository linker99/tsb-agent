#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "tcs_store.h"
#include "debug.h"
#include "crypto/sm/sm3.h"


void usage()
{
	printf ("\n"
			" Usage: ./nv_named_read [options]\n"
			" options:\n"
			"	 	 -N <name>			- The name for nv(defalut:10)\n"
			"		 -p <passwd>			- The nv password\n"
			"    eg. ./nv_named_read -N one -p 123456\n"
			"    eg. ./nv_named_read -N two -p 123456\n"
			"\n");
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int length = 4096;
	char *name = NULL;
	char data[4096] = {0};
	uint8_t *passwd = NULL;
 	

	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "N:p:")) != -1)
	{
		switch (ch) 
		{
			case 'N':
				name = optarg;
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

	if(passwd == NULL || name == NULL){
		usage ();
		return -1;
	}	
		
	ret = tcs_nv_named_read((const char *)name, &length, data,passwd);
	if(ret){
		printf("Error tcs_nv_named_read fail! ret:0x%016X!\n",ret);
		return -1;
	}
//	printf("%s\n",data);
	return ret;	
}


