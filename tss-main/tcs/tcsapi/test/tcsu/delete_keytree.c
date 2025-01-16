#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"
#include "file.h"

void usage()
{
	printf ("\n"
			" Usage: ./delete_keytree [options]\n"
			" options:\n"
			"	 	 -k <keypath>		- The key path\n"
			"    eg. ./delete_keytree -k s://a/b\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	char *key_path = NULL;

	if (argc != 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			default:
				usage();
				break;				
		}
	}
	if(!key_path){
		usage();
		return -1;
	}
	
	ret = tcs_delete_keytree((const char *)key_path);
	if(ret){
		printf("Error tcs_delete_keytree fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}
	return ret;
	
}



