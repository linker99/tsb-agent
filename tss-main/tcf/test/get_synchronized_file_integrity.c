#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_file_integrity.h"
#include "tcsapi/tcs_file_integrity.h"
#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_attest_def.h"


static void usage ()
{
	printf ("\n"
			" Usage: ./get_synchronized_file_integrity [options]\n"
			" options:\n"
			"        -M <mijor>           - The start major version\n"
			"        -m <mijor>      - The end major version\n"
			"        -S <sub>      - The start sub version \n"
			"        -s <sub>     - The end sub version\n"
			"    eg. ./get_synchronized_file_integrity -M 0 -m 512 -S 0 -s 512\n"
			"\n");
}

int main(int argc,char **argv){

	int i = 0;
	int ch = 0;
	int ret = 0;	
	int num = 0;
	struct sync_version version;
	struct file_integrity_sync *file_integrity = NULL;
	

	if(argc != 9){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "M:m:S:s:")) != -1)
	{
		switch (ch) 
		{
			case 'M':
				version.smajor = atoi(optarg);
				break;
			case 'm':
				version.emajor = atoi(optarg);
				break;
			case 'S':
				version.sminor = atoi(optarg);
				break;
			case 's':
				version.eminor = atoi(optarg);
				break;
			default:
				usage ();
				return -1;
		}
	}
	
	ret = tcf_get_synchronized_file_integrity(&version,&file_integrity,&num);		
	if(ret){
		printf("[Error] tcf_get_synchronized_file_integrity ret:0x%08X\n",ret);
		return -1;
	}
	for(; i < num; i++){
		printf("\n\n");
		printf("major:0x%016lX\n",(file_integrity + i)->smajor);
		printf("sub:0x%08X\n",(file_integrity + i)->sminor);
		printf("action:%d\n",(file_integrity + i)->action);
		httc_util_dump_hex((const char *)"data",(file_integrity + i)->data,(file_integrity + i)->length);
	}

	ret = tcf_free_synchronized_file_integrity (&file_integrity,num);
	if(ret){
		printf("[Error] tcf_free_synchronized_file_integrity ret:0x%08X\n",ret);
		return -1;
	}

	return 0;
}
