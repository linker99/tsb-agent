#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_key.h"
#include "httcutils/mem.h"
#include "httcutils/file.h"
#include "../src/tutils.h"

void usage()
{
	printf ("\n"
			" Usage: ./import_keytree [options]\n"
			" options:\n"
			"	 	 -k <keypath>		- The key path\n"
			"		 -n <name>		- The import file name\n"
			"    eg. ./import_keytree -k s://a/b -n Export\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	unsigned long length = 0;
	unsigned char *importbuf = NULL;
	uint8_t pbuff[2048] = {0};
	char *key_path = NULL;
	char *file = NULL;
	uint32_t source = POLICY_SOURCE_HOST;

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
	if(key_path == NULL || file == NULL ){
			usage ();
			return -1;
	}
	importbuf = httc_util_file_read_full((unsigned char *)file,&length);
	memcpy(pbuff,importbuf,length);
	if(importbuf) httc_free(importbuf);

	
	
	ret = tcf_import_keytree((const char *)key_path,pbuff,(int)length,source);
	if(ret){
		printf("Error tcf_import_keytree fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	
	return ret;	
}



