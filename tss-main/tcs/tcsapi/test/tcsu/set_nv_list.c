#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "mem.h"
#include "file.h"
#include "debug.h"
#include "tcs_store.h"

#define MAX_NV_NAME_SIZE 	256

void usage()
{
	printf ("\n"
			" Usage: ./set_nv_list [options]\n"
			" options:\n"
			"		 -f <file>		- The import file name\n"
			"		 -n <number>		- The nv info number\n"
			"    eg. ./set_nv_list -f nvinfos -n 5\n"			
			"\n");
}
#pragma pack(push, 1)
struct nv_save_info{
	uint32_t index;
	int size;	
	char name[MAX_NV_NAME_SIZE];
	unsigned int policy_flags;
	unsigned int user_or_group;
	uint64_t prlength;
	uint8_t data[0];
};
#pragma pack(pop)

static int number = 0;

static void show_nv_list(struct nv_info *infos,int number){

	int i = 0;
//	httc_util_dump_hex((const char *)"nv list", infos, 1000);
	for(i = 0; i < number;i++){
		printf("---------------cycle:%d----------\n",i);
		printf("index:%d\n",infos[i].index);
		printf("name:%s\n",infos[i].name);
		printf("size:%d\n",infos[i].size);
		printf("policy->flags:0x%08X\n",infos[i].auth_policy.policy_flags);
		printf("policy->process_or_role:%s\n",infos[i].auth_policy.process_or_role);
		printf("policy->user_or_group:%d\n",infos[i].auth_policy.user_or_group);		
	} 
}

static void nv_info_convert(struct nv_info *info, struct nv_save_info *save_info, int *length){

	int info_length = 0;
	struct nv_info *curinfo = NULL;
	struct nv_save_info *cursaveinfo = NULL;
	//httc_util_dump_hex((const char *)"save_info", save_info, *length);
	while(info_length < *length){
			curinfo = (struct nv_info *)((uint8_t *)info + number*sizeof(struct nv_info));
			cursaveinfo = (struct nv_save_info *)((uint8_t *)save_info + info_length);
			//httc_util_dump_hex((const char *)"cursaveinfo", cursaveinfo, sizeof(struct nv_save_info));
			curinfo->index = cursaveinfo->index;
			curinfo->size = cursaveinfo->size;
			//httc_util_dump_hex((const char *)"(info + number)->name", (info + number)->name, MAX_NV_NAME_SIZE);
			//httc_util_dump_hex((const char *)"cursaveinfo->name", cursaveinfo->name, MAX_NV_NAME_SIZE);
			memcpy(curinfo->name,cursaveinfo->name,MAX_NV_NAME_SIZE);			
			curinfo->auth_policy.policy_flags = cursaveinfo->policy_flags;
			curinfo->auth_policy.user_or_group = cursaveinfo->user_or_group;

			if(cursaveinfo->prlength){
				if(NULL == (curinfo->auth_policy.process_or_role = httc_malloc(cursaveinfo->prlength + 1))){
					httc_util_pr_error("httc_malloc error length:%ld\n ",cursaveinfo->prlength + 1);
				}
				memcpy(curinfo->auth_policy.process_or_role,cursaveinfo->data,cursaveinfo->prlength);
			}
			info_length += sizeof(struct nv_save_info) + cursaveinfo->prlength;
			number ++;
		}		
		*length = number * sizeof(struct nv_info);
}

int main(int argc, char **argv){
	int ret = 0;
	int ch = 0;
	int info_number = 0;
	unsigned long length = 0;
	int infolength = 0;
	uint8_t *array = NULL;
	uint8_t *infos = NULL;
	char *file = NULL;

	if (argc != 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "f:n:")) != -1)
	{
		switch (ch) 
		{
			case 'f':
				file = optarg;
				break;
			case 'n':
				info_number = atoi(optarg);
				break;
			default:
				usage();
				break;				
		}
	}
	if(file == NULL ){
			usage ();
			return -1;
	}

	infos = httc_util_file_read_full((unsigned char *)file,(unsigned long *)&length);
	if(infos == NULL) {
		printf("read error");
		return -1;
	}	
		
	if(NULL == (array = httc_malloc(info_number * sizeof(struct nv_info)))){
				httc_util_pr_error("httc_malloc error");
				return -1;
	}
	
	memset(array,0,info_number * sizeof(struct nv_info));
	infolength = length;
	nv_info_convert((struct nv_info *)array, (struct nv_save_info *)infos, &infolength);	
	//show_nv_list((struct nv_info *)array, number);	
	ret = tcs_set_nv_list((struct nv_info *)array,number);
	if(ret){
		printf("Error tcs_set_nv_list fail! ret:0x%08X(%d)!\n",ret,ret);
		if(infos) httc_free(infos);
		tcs_free_nv_list((struct nv_info *)array, number);
		return -1;
	}
	if(infos) httc_free(infos);
	tcs_free_nv_list((struct nv_info *)array, number);	
	return ret;	
}



