#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_constant.h"
#include "tcs_process.h"
#include "tcs_process_def.h"


void show_process(struct process_identity *ids,int num){

	int i = 0;
	int j = 0;
	int op = 0;
	int hash_len = 0;
	struct process_identity *cur = NULL;
	
	for(;i < num; i++){
		cur = (struct process_identity *)((uint8_t *)ids + op);
		printf("================RUN:%d================\n",i);
		printf ("ids[%d] name: %s\n",i, cur->data + (1 + ntohs(cur->be_lib_number)) * ntohs(cur->be_hash_length));
		printf ("ids[%d] specific_libs: %s\n",i, cur->specific_libs == 0 ? "USE" : "UNUSE");
		printf ("ids[%d] lib number: %d\n",i, (uint32_t)ntohs(cur->be_lib_number));
		hash_len = (int)ntohs(cur->be_hash_length);
		for(j = 0; j < ntohs(cur->be_lib_number) + 1;j++){
			printf("[%d-%d]\n",i,j);
			httc_util_dump_hex ("HASH IS", cur->data + (j * hash_len) , hash_len);
		}
		op += HTTC_ALIGN_SIZE(hash_len * (1 + ntohs(cur->be_lib_number))  + cur->name_length + sizeof(struct process_identity), 4);
		
	}
	if(ids) httc_free(ids);
}

int main ()
{
	int ret = 0;
	int num = 0;
	int length = 0;
	struct process_identity *ids = NULL;
	
	ret = tcs_get_process_ids(&ids,&num,&length);
	if(ret){
		printf("[Error] tcs_get_process_ids ret:0x%08x\n",ret);
		return -1;
	}
	printf("tcs_get_process_ids success!\n");
	show_process(ids,num);
	return 0;
}

