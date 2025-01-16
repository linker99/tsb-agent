#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_constant.h"
#include "tcs_file_protect.h"
#include "tcs_file_protect_def.h"


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0],\
	((unsigned char *)&addr)[1],\
	((unsigned char *)&addr)[2],\
	((unsigned char *)&addr)[3]
	
void show_file_protect_policy(struct file_protect_item *policies, int length ,int num){

	int i = 0;
	int j = 0;
	int op = 0;
	int opt = 0;
	int number = 0;
	struct file_protect_item *cur_item = NULL;
	struct file_protect_privileged_process *cur = NULL;

 	for (j = 0 ; j < num; j++){
		cur_item = (struct file_protect_item *)((uint8_t *)policies + op);
		printf ("policies->is_default_policy: %s\n", (cur_item->measure_flags >> 7) ? "YES" : "NO");
		printf ("policies->measure_flags: %s\n", (cur_item->measure_flags & 0x7F) == 1 ? "FILE_PROTECT_MEASURE_ENV" : "FILE_PROTECT_MEASURE_PROCESS");
		printf ("policies->type: %s\n", cur_item->type == 0 ? "FILE_WRITE_PROTECT" : "FILE_READ_PROTECT");
		printf ("policies->be_privileged_process_num: %d\n", ntohs (cur_item->be_privileged_process_num));
		printf ("policies->path: %s\n", cur_item->path);
		number = (int)ntohs(cur_item->be_privileged_process_num);
		opt = 0;	
		for(i = 0;i < number; i++){
			cur = (struct file_protect_privileged_process *)((uint8_t *)cur_item->privileged_processes + opt);
			printf ("be_privi_type: %s\n", ntohl(cur->be_privi_type) == 0 ? "PRIVI_ALL" : "PRIVI_READ_ONLY");	
			printf ("path: %s\n", cur->path);
			httc_util_dump_hex ("hash", cur->hash , 32);
			printf("\n\n");
			opt += sizeof(struct file_protect_privileged_process);			
		}

		op += opt;
		op += sizeof(struct file_protect_item);
		HTTC_ALIGN_SIZE(op,4);
		
		if(op > length) break;
	}
	
	if(policies) httc_free(policies);
}

int main(int argc,char **argv){

	int ret = 0;
	int length = 0;
	int num = 0;
	struct file_protect_item *policy = NULL;

	ret = tcs_get_file_protect_policy(&policy,&num ,&length);
	if(ret){
		printf("[Error] tcs_get_tnc_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_file_protect_policy(policy, length , num);
	return 0;
}

