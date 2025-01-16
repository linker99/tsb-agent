#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file.h"
#include "tcs_store.h"

int tcs_save_mem_data(uint32_t index, int length, unsigned char *data, char *usepasswd);

void usage()
{
	printf ("\n"
			" Usage: ./save_mem_data [options]\n"
			" options:\n"
			"	 	 -i <index>		- The index\n"
			"	 	 -p <passwd>		- The password\n"
			"	 	 -d <data>		- Data you want to store\n"
			"	 	 -f <file>		- File you want to store\n"
			"    eg. ./save_mem_data -i 66 -p 123 -d helloworld!\n"			
			"\n");
}


int main(int argc, char **argv){

	int ch = 0;
	int ret = 0;
	int length = 0;
	unsigned char *data = NULL;
	char *usepasswd = NULL;
	char *file = NULL;
	uint32_t index = 0;
	unsigned long datalen = 0;
		
	if(argc != 7){
		usage();
		return -1;
	}

	while((ch = getopt(argc,argv, "i:p:d:f:"))!= -1){

		switch(ch){
			case 'i':
				index = atoi(optarg);				
				break;
			case 'p':
				usepasswd = optarg;				
				break;
			case 'd':
				data = optarg;
				break;
			case 'f':
				file = optarg;
				break;
			default:
				usage();
				break;
		}		
	}

	if(file){
		data = httc_util_file_read_full((const char *)file, &datalen);
		if(!data){
			printf("httc_util_file_read_full error\n");
			return -1;
		}
		length = datalen;
	}else{
		length = strlen((const char *)data);
	}

	if(data == NULL || usepasswd == NULL){
		usage();
		return -1;
	}
	ret = tcs_save_mem_data(index,length,data,usepasswd);
	if(ret){
		printf("tcs_save_mem_data error 0x%04X(%d)\n",ret,ret);
		return -1;
	}

	return ret;
}


