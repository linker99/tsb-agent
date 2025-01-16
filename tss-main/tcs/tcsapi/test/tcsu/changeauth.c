#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./changeauth [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The key path\n"
			"		 -n <passwd>			- The key path newpassword\n"
			"		 -o <passwd>			- The key path oldpassword\n"
			"    eg. ./changeauth -k s://a/b -o 123456 -n 123123\n"			
			"\n");
}



int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	char *oldpasswd = NULL;
	char *newpasswd = NULL;
	char *keypath = NULL;

	if (argc < 3){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:n:o:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				keypath = optarg;
				printf ("keypath: %s\n", keypath);
				break;
			case 'n':
				newpasswd = optarg;
				printf ("newpasswd: %s\n", newpasswd);
				break;
			case 'o':
				oldpasswd = optarg;
				printf ("oldpasswd: %s\n", oldpasswd);
				break;				
			default:
				usage();			
			}

	}
	if(keypath == NULL){
			usage ();
			return -1;
	}
	
	ret = tcs_change_leaf_auth((unsigned char *)keypath,(unsigned char *)oldpasswd,(unsigned char *)newpasswd);
	if(ret){
		printf("tcs_change_leaf_auth fail!\n");
	}
	return ret;	
}


