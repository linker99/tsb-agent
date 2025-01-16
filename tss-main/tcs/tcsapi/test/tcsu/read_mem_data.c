#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "tcs_store.h"

int tcs_read_mem_data(uint32_t index, int *length_inout, unsigned char *data, char *usepasswd);

void usage()
{
	printf ("\n"
			" Usage: ./save_mem_data [options]\n"
			" options:\n"
			"	 	 -i <index>		- The index\n"
			"	 	 -p <passwd>		- The password\n"
			"    eg. ./save_mem_data -i 66 -p 123\n"			
			"\n");
}


int main(int argc, char **argv){

	int ch = 0;
	int ret = 0;
	int length = 4096;
	unsigned char *data = NULL;
	char *usepasswd = NULL;
	uint32_t index = 0;
		
	if(argc != 5){
		usage();
		return -1;
	}

	while((ch = getopt(argc,argv, "i:p:"))!= -1){

		switch(ch){
			case 'i':
				index = atoi(optarg);				
				break;
			case 'p':
				usepasswd = optarg;				
				break;
			default:
				usage();
				break;
		}		
	}
	
	if(usepasswd == NULL){
		usage();
		return -1;
	}
	data = malloc(4096);
	ret = tcs_read_mem_data(index,&length,data,usepasswd);
	if(ret){
		printf("tcs_read_mem_data error 0x%04X(%d)\n",ret,ret);
		return -1;
	}
	httc_util_dump_hex((const char *)"mem_data", data, length);
	if(data) free(data);
	return ret;
}

