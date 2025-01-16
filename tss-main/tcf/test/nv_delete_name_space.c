#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_store.h"
#include "../src/tutils.h"

void usage()
{
	printf ("\n"
			" Usage: ./nv_delete_space [options]\n"
			" options:\n"
			"	 	 -N <name>			- The name for nvspace\n"
			"		 -w <ownerpasswd>			-The ownerpasswd\n"
			"    eg. ./nv_delete_space -N 6 -w 123\n"
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	char *name = NULL;
	uint8_t *ownerpasswd = NULL;
	uint32_t source = POLICY_SOURCE_HOST;

	if (argc != 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "N:w:")) != -1)
	{
		switch (ch) 
		{
			case 'N':
				name = optarg;
//				printf ("keypath: %s\n", keypath);
				break;
			case 'w':
				ownerpasswd = optarg;
//				printf ("type: %d\n", type);
				break;
			default:
				usage();			
			}

	}

	if(ownerpasswd == NULL || name == NULL){
		usage ();
		return -1;
	}
	
	
	ret = tcf_nv_delete_named_space(name,ownerpasswd,source);
	if(ret){
		printf("Error tcf_nv_delete_named_space fail! ret:0x%016X!\n",ret);
		return -1;
	}

	return ret;	
}

