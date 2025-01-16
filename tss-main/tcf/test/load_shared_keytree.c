#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcfapi/tcf_key.h"





void usage()
{
	printf ("\n"
			" Usage: ./load_shared_keytree [options]\n"
			" options:\n"
			"	 	 -p <passwd>		- The nv password\n"
			"    eg. ./load_shared_keytree -p 123456\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;	
	char *nvpass = NULL;

	if (argc != 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "p:")) != -1)
	{
		switch (ch) 
		{
			case 'p':
				nvpass = optarg;
//				printf ("ownerpass: %s\n", ownerpass);
				break;
			default:
				usage();
				break;				
		}
	}

	if(nvpass == NULL ){
			usage ();
			return -1;
	}
	ret = tcf_load_shared_keytree((unsigned char *)nvpass);
	if(ret){
		printf("Error tcf_save_shared_keytree fail! ret:0x%08X(%d)!\n",ret,ret);
		return -1;
	}	

	return 0;
	
}


