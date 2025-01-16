#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "tcs_store.h"
#include "mem.h"
#include "file.h"
#include "crypto/sm/sm3.h"


void usage()
{
	printf ("\n"
			" Usage: ./nv_named_write [options]\n"
			" options:\n"
			"	 	 -N <nvname>			- The name for nv(defalut:10)\n"
			"	 	 -d <data>			- The data want to write\n"
			"		 -F <filename>			-The file want to write\n"
			"		 -p <passwd>			- The nv password\n"
			"    eg. ./nv_named_write -N one -d helloworld! -p 123456\n"
			"    eg. ./nv_named_write -N two -F one -p 123456\n"
			"\n");
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	unsigned long length = 0;
	char *data = NULL;
	char *file = NULL;
	char *name = NULL;
	uint8_t *passwd = NULL;	

	if (argc < 7 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "N:d:F:p:")) != -1)
	{
		switch (ch) 
		{
			case 'N':
				name = optarg;
//				printf ("keypath: %s\n", keypath);
				break;
			case 'd':
				data = optarg;
				length = strlen((const char *)data);
//				printf ("keypath: %s\n", keypath);
				break;
			case 'F':
				file = optarg;
//				printf ("type: %d\n", type);
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
	
	if(file){
		data = httc_util_file_read_full((const char *)file, &length);
		if(!data) return -1;
	}
	
	ret = tcs_nv_named_write((const char *)name, length, data,passwd);
	if(ret){
		printf("tcs_nv_named_write fail! ret:0x%08X!\n",ret);
		return -1;
	}
	if(file) {
		if(data) httc_free(data);
	}
	return ret;	
}

