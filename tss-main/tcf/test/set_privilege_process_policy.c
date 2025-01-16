#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "tcfapi/tcf_fileacl.h"
#include "tcsapi/tcs_constant.h"

#include "httcutils/debug.h"
#include "httcutils/file.h"
#include "httcutils/mem.h"
#include "httcutils/convert.h"

#include "crypto/sm/sm3.h"


void usage()
{
	printf ("\n"
			" Usage: ./set_privilege_process_policy [options]\n"
			" options:\n"
			"	 	 -n	<number>			- The policy number\n"
			"		 -p <pattern>			- The pattern path\n"
			"    eg. ./set_privilege_process_policy -n 1 -p /usr/bin/ls\n"
			"    eg. ./set_privilege_process_policy -n 0\n"
			"\n");
}

static void show_policy(char *data,uint64_t length){
	int i = 1;
	int num = 0;
	int op = 0;
	int len = 0;
	char *pattern = NULL;
	char hash[DEFAULT_HASH_SIZE] = {0};

	httc_util_dump_hex("privilege_process_policy",data,(int)length);

	memcpy(&num,data,sizeof(int));
	op += sizeof(int);
	num = ntohl(num);
	printf("privilege_process_policy num is %d\n",num);
	
	if(num){
		do{
			memcpy(&len,data + op,sizeof(int));
			len =  ntohl(len);
			printf("\n\npolicy[%d] length:%d \n",i,len);
			op += sizeof(int);
			
			memcpy(hash,data + op,DEFAULT_HASH_SIZE);
			op += DEFAULT_HASH_SIZE;
			httc_util_dump_hex("HASH",hash,DEFAULT_HASH_SIZE);
			
			pattern = httc_malloc(len);
			memset(pattern,0,len);
			memcpy(pattern,data + op,len);
			printf("policy[%d] pattern:%s \n",i,pattern);
			if(pattern) httc_free(pattern);
			
			op += len;
			i += 1;
			if(op >= length) break;
		
		}while(1);
	}

	if(data) httc_free(data);
}

int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	int num = 0;
	int cur = 0;
	int i = 0;
	char *data = NULL;
	unsigned long datalength = 0;
	char *file = HTTC_TSS_CONFIG_PATH"privilege_process.data";
	struct tcf_privilege_process ppolicy[20] = {0};

	if(argc < 3){
		usage();
		return -1;
	}

	while ((ch = getopt(argc, argv, "n:p:")) != -1)
	{
		switch (ch) 
		{
			case 'n':
				num = atoi(optarg);
				break;
			case 'p':
				ppolicy[0].pattern = optarg;
				ppolicy[0].length = strlen((const char *)ppolicy[0].pattern) + 1;
				sm3((const unsigned char *)ppolicy[0].pattern,ppolicy[0].length,ppolicy[0].hash);

				if(num > 1){
					cur = optind - 1;
					for (;i < num;i++){
						ppolicy[i].pattern = argv[cur];
						ppolicy[i].length = strlen((const char *)ppolicy[i].pattern) + 1;
						sm3((const unsigned char *)ppolicy[i].pattern,ppolicy[i].length,ppolicy[i].hash);
						cur += 1;
					}

				}
				break;				
			default:
				usage();
				break;
			}

	}

	if(num){
		ret = tcf_set_privilege_process_policy(ppolicy,num);
		if(ret){
			printf("[Error] tcf_set_privilege_process_policy ret:0x%08X(%d)\n",ret,ret);
			return -1;			
		}
	}else{
		ret = tcf_set_privilege_process_policy(NULL,num);
		if(ret){
			printf("[Error] tcf_set_privilege_process_policy ret:0x%08X(%d)\n",ret,ret);
			return -1;			
		}
	}

	printf("file name %s\n",file);
	data = httc_util_file_read_full((const char*)file,&datalength);
	if(data == NULL){
		printf("[Error] httc_util_file_read_full %s\n",file);
		return -1;
	}

	show_policy(data,datalength);

	return 0;
}

