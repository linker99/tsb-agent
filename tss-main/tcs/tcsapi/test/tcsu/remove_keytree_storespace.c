#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./remove_keytree_storespace [options]\n"
			" options:\n"
			"	 	 -w <passwd>		- The owener password\n"
			"    eg. ./remove_keytree_storespace -w 123\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;	
	char *ownerpass = NULL;

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "w:")) != -1)
	{
		switch (ch) 
		{
			case 'w':
				ownerpass = optarg;
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			default:
				usage();
				break;				
		}
	}

	if(ownerpass == NULL ){
			usage ();
			return -1;
	}
	
	ret = tcs_remove_shared_keytree_storespace((unsigned char *)ownerpass);
	if(ret){
		printf("Error tcs_remove_shared_keytree_storespace fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	

	return 0;
	
}

