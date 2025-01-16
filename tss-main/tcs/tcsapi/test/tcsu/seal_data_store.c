#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "tcs_key.h"
#include "file.h"
#include "debug.h"

void usage()
{
	printf ("\n"
			" Usage: ./seal_data_store [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -d <data>			- Data to be encapsulated or unsealed\n"
			"		 -p <passwd>			- The key path password\n"
			"		 -s <filename>			- The name of sealfile\n"
			"		 -S <filename>			- The name for file to seal\n"
			"    eg. ./seal_data_store -k s://seal/a -d 123456789 -p 123456 -s Seal\n"
			"    eg. ./seal_data_store -k s://seal/b -d 123456789 -p 123456 -s Seal\n"
			"\n");
}

static void printf_time(char *str){
	time_t now ;
    struct tm *tm_now ;
    time(&now) ;
    tm_now = localtime(&now) ;//get date
    printf("%s\n",str);
  	printf("datetime: %d-%d-%d %d:%d:%d\n",tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec) ;
}


int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int ilength = 0;	
	int olen_inout = 4096;
	int unseallength = 4096;
	char *passwd = NULL;	
	char *key_path = NULL;
	char *filename = NULL;
	char *ibuffer = NULL;
	char obuffer[4096];
	char unsealbuffer[4096];
	char *sealfilename = NULL;
	unsigned long datalength = 0;

	if (argc < 9 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:p:s:S:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'd':
				ibuffer = optarg;
				ilength = strlen((const char*)ibuffer);
//				printf ("ibuffer: %s\n", ibuffer);
				break;
			case 'p':
				passwd = optarg;
//				printf ("passwd: %s\n", passwd);
				break;
			case 's':
				filename = optarg;
//				printf ("filename: %s\n", filename);
				break;
			case 'S':
				sealfilename = optarg;
				ibuffer = httc_util_file_read_full((const char *)sealfilename,&datalength);
				if(ibuffer == NULL){
					printf("httc_util_file_read_full fail! %s!\n",sealfilename);
					return -1;
				}
				ilength = (int)datalength;
				break;
			default:
				usage();
				break;				
		}
	}

	if(passwd == NULL || key_path == NULL || filename == NULL){
			usage ();
			return -1;
	}
	printf_time("tcs_seal_data_store start");
	ret = tcs_seal_data_store((unsigned char *)key_path,(unsigned char *)ibuffer, ilength,(unsigned char *)filename,(unsigned char *)passwd);
	printf_time("tcs_seal_data_store end");
	if(ret){
		printf("tcs_seal_data_store fail! ret:0x%08X!\n",ret);
		return -1;
	}
	
	return 0;
	
}



