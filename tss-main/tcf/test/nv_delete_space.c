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
			"	 	 -I <index>			- The index for nv(defalut:10)\n"
			"		 -w <ownerpasswd>			-The ownerpasswd\n"
			"    eg. ./nv_delete_space -I 6 -w 123\n"
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	uint32_t index = 10;
	uint8_t *ownerpasswd = NULL;
	uint32_t source = POLICY_SOURCE_HOST;

	if (argc != 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "I:w:")) != -1)
	{
		switch (ch) 
		{
			case 'I':
				index = atoi(optarg);
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

	if(ownerpasswd == NULL){
		usage ();
		return -1;
	}
	
	
	ret = tcf_nv_delete_space(index,ownerpasswd,source);
	if(ret){
		printf("Error tcf_nv_delete_space fail! ret:0x%016X!\n",ret);
		return -1;
	}

	return ret;	
}

