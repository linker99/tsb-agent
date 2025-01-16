#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./create_keytree_storespace [options]\n"
			" options:\n"
			"	 	 -w <passwd>		- The owener password\n"
			"		 -n <passwd>		- The nv password\n"
			"		 -s  <size>		    - The size of the storespace(byte)\n"
			"    eg. ./create_keytree_storespace -w 123 -n 123456 -s 10240\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int size = 0;	
	char *ownerpass = NULL;
	char *nvpasswd = NULL;

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "w:n:s:")) != -1)
	{
		switch (ch) 
		{
			case 'w':
				ownerpass = optarg;
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			case 'n':
				nvpasswd = optarg;
//				printf ("nvpasswd: %s\n", nvpasswd);
				break;
			case 's':
				size = atoi(optarg);
//				printf ("size: %d\n", size);
				break;
			default:
				usage();
				break;				
		}
	}

	if(ownerpass == NULL || nvpasswd == NULL ){
			usage ();
			return -1;
	}
	
	ret = tcs_create_shared_keytree_storespace((unsigned char *)ownerpass, size,(unsigned char *)nvpasswd);
	if(ret){
		printf("Error tcm_create_shared_keytree_storespace fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	

	return 0;
	
}

