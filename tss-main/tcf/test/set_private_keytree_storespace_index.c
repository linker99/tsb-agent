#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"





void usage()
{
	printf ("\n"
			" Usage: ./set_private_keytree_storespace_index [options]\n"
			" options:\n"
			"	 	 -i <index>		- The private keytree storespace index\n"
			"    eg. ./set_private_keytree_storespace_index -i 66\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;	
	uint32_t nvindex = 0;

	if (argc != 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "i:")) != -1)
	{
		switch (ch) 
		{
			case 'i':
				nvindex = atoi(optarg);
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			default:
				usage();
				break;				
		}
	}

	
	ret = tcf_set_private_keytree_storespace_index(nvindex);
	if(ret){
		printf("Error tcf_set_private_keytree_storespace_index fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	

	return 0;
	
}

