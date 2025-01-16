#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "mem.h"
#include "tcs_key.h"

void usage()
{
	printf ("\n"
			" Usage: ./get_key_info [options]\n"
			" options:\n"
			"	 	 -k	<keypath>			- The seal key path\n"
			"		 -o <operaction>		- 0:tcs_get_keyinfo(default)  1:tcs_get_keyinfo_path\n"
			"    eg. ./get_key_info -k s://a/b -o 0\n"			
			"\n");
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int opt = 0;
	int i = 0;
	int number = 0;
	struct key_info info;
	struct key_info *infos = NULL;
	char *key_path = NULL;

	if (argc < 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:d:p:o:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
				printf ("keypath: %s\n", key_path);
				break;
			case 'o':
				opt = atoi(optarg);
				break;
			default:
				usage();
				break;				
		}
	}
	if(key_path == NULL){
			usage ();
			return -1;
	}

	if(opt == 0){
		ret = tcs_get_keyinfo((unsigned char *)key_path, &info);
		if(ret){
		
			printf("tcm_get_keyinfo fail!\n");
			return -1;
		}
		printf("key_type:%d\n",info.key_type);
		printf("key_use:%d\n",info.key_use);
		printf("oirgin:%d\n",info.origin);
		printf("key_size:%d\n",info.key_size);
		printf("migratable:%d\n",info.migratable);
		printf("attribute:%d\n",info.attribute);
		
	}else if(opt == 1){
	    ret = tcs_get_keyinfo_path((unsigned char *)key_path,&infos,&number);
		if(ret){
			printf("tcm_get_keyinfo_path fail!\n");
//			if(infos) httc_free(infos);
			return -1;
		}else{
			for(;i < number;i++){
				printf("------Serial:%d---------\n",i);
				printf("key_type:%d\n",(infos + i)->key_type);
				printf("key_use:%d\n",(infos + i)->key_use);
				printf("origin:%d\n",(infos + i)->origin);
				printf("key_size:%d\n",(infos + i)->key_size);
				printf("migratable:%d\n",(infos + i)->migratable);
				printf("attribute:%d\n",(infos + i)->attribute);
			}
			if(infos) httc_free(infos);
		}
	}
	return 0;	
}


