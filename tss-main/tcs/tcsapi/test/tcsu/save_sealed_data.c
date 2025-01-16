#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"
#include "file.h"
#include "mem.h"


void usage()
{
	printf ("\n"
			" Usage: ./save_sealed_data [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"	 	 -d	<sealdatafile>			- The sealed data file name\n"
			"		 -s <filename>			- The name of sealfile\n"
			"    eg. ./save_sealed_data -k s://seal/a -d a.seal -s a.seal\n"
			"\n");
}


int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	char *key_path = NULL;
	char *filename = NULL;
	char *sealedfilename = NULL;
	char *ibuffer = NULL;
	unsigned long ilength = 0;

	if (argc < 7 || !argc%2){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:s:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("keypath: %s\n", key_path);
				break;
			case 'd':
				sealedfilename = optarg;
				ibuffer = httc_util_file_read_full((const char *) sealedfilename, &ilength);
//				printf ("ibuffer: %s\n", ibuffer);
				break;
			case 's':
				filename = optarg;
//				printf ("filename: %s\n", filename);
				break;
			default:
				usage();
				break;				
		}
	}

	if( ibuffer == NULL || key_path == NULL || filename == NULL ){
			usage ();
			return -1;
	}

	ret = tcs_save_sealed_data((unsigned char *)key_path,(unsigned char *)ibuffer, (int)ilength,(unsigned char *)filename);
	if(ret){
		printf("tcs_save_sealed_data fail!\n");
		if(ibuffer) httc_free(ibuffer);
		return -1;
	}
	if(ibuffer) httc_free(ibuffer);
	return 0;
	
}



