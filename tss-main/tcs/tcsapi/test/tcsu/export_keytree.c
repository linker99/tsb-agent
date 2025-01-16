#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "mem.h"
#include "tcs_key.h"
#include "file.h"
#include "debug.h"


void usage()
{
	printf ("\n"
			" Usage: ./export_keytree [options]\n"
			" options:\n"
			"	 	 -k <keypath>		- The key path\n"
			"		 -n <name>		- The export file name\n"
			"    eg. ./export_keytree -k s://a/b -n Export\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int length = 0;
	unsigned char *exportbuf = NULL;
	char *key_path = NULL;
	char *file = NULL;

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:n:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			case 'n':
				file = optarg;
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
	ret = tcs_export_keytree((const char *)key_path,&exportbuf,&length);
	if(ret){
		printf("Error tcs_save_shared_keytree fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}
//	httc_util_dump_hex((const char *)"export",exportbuf,length);
	ret = httc_util_file_write((const char *)file,(const char *)exportbuf,(unsigned int)length);
	if(ret == length) ret = 0;
	if(exportbuf) httc_free(exportbuf);
	return ret;
	
}



