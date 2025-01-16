#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "tcfapi/tcf_store.h"
#include "httcutils/debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./nv_read [options]\n"
			" options:\n"
			"	 	 -I <index>			- The index for nv(defalut:10)\n"
			"		 -p <passwd>			- The nv password\n"
			"    eg. ./nv_read -I 6 -p 123456\n"
			"\n");
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int length = 4096;
	uint32_t index = 10;	
	char data[4096] = {0};
	uint8_t *passwd = NULL;	

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "I:p:")) != -1)
	{
		switch (ch) 
		{
			case 'I':
				index = atoi(optarg);
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
	ret = tcf_nv_read(index, &length, data,passwd);
	if(ret){
		printf("Error tcf_nv_read fail! ret:0x%016X!\n",ret);
		return -1;
	}
	printf("length:%d %s\n",length,data);
	return ret;	
}

