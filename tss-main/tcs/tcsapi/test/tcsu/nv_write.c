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
			" Usage: ./nv_write [options]\n"
			" options:\n"
			"	 	 -I <index>			- The index for nv(defalut:10)\n"
			"	 	 -d <data>			- The data want to write\n"
			"		 -F <filename>			-The file want to write\n"
			"		 -p <passwd>			- The nv password\n"
			"    eg. ./nv_write -I 6 -d helloworld! -p 123456\n"
			"\n");
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	unsigned long length = 0;
	uint32_t index = 10;
	char *data = NULL;
	char *file = NULL;
	uint8_t *passwd = NULL;	

	if (argc < 5 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "I:d:F:p:")) != -1)
	{
		switch (ch) 
		{
			case 'I':
				index = atoi(optarg);
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
	
	if(file){
		data = httc_util_file_read_full((const char *)file, &length);
		if(!data) return -1;
	}
	
	ret = tcs_nv_write(index, length, data,passwd);
	if(ret){
		printf("Error tcs_nv_write fail! ret:0x%016X!\n",ret);
		return -1;
	}
	if(file) {
		if(data) httc_free(data);
	}
	return ret;	
}

