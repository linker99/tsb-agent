#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_key.h"
#include "../src/tutils.h"





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
	uint32_t source = POLICY_SOURCE_HOST;

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
	
	
	ret = tcf_remove_shared_keytree_storespace((unsigned char *)ownerpass,source);
	if(ret){
		printf("Error tcf_remove_shared_keytree_storespace fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	

	return 0;
	
}

