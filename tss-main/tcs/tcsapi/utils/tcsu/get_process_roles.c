#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_constant.h"
#include "tcs_process.h"
#include "tcs_process_def.h"

void show_role(struct process_role *roles,int num){
	
	int i = 0;
	int j = 0;
	int pop = 0;
	int op = 0;
	int name_number = 0;
	unsigned char name[128];
	struct process_role *pcur = NULL;
	struct role_member *cur = NULL;
	for(;i < num;i++){
		pcur = (struct process_role *)((uint8_t *)roles + pop);
		printf("================RUN:%d================\n",i);
		memset(name,0,128);
		op = ntohl(pcur->be_name_length);
		memcpy(name,pcur->members,op);
		printf("name:%s\n",name);
		name_number = ntohl(pcur->be_members_number);
		for(j = 0;j < name_number;j++){
			cur = (struct role_member *)(pcur->members + op);
			memset(name,0,128);
			memcpy(name,cur->name,cur->length);
			printf("%d:%s\n",j,name);
			op += cur->length + sizeof(struct role_member);
		}
		pop += HTTC_ALIGN_SIZE(op + sizeof(struct process_role), 4);
		printf("\n\n");		 
	}
	if(roles) httc_free(roles);
}

int main ()
{
	int ret = 0;
	int num = 0;
	int length = 0;
	struct process_role *roles = NULL;

	ret = tcs_get_process_roles(&roles,&num,&length);
//	httc_util_dump_hex ("roles", roles , length);
	if(ret){
		printf("[Error] tcs_get_process_roles ret:0x%08x\n",ret);
		return -1;
	}
	printf("tcs_get_process_roles success!\n");
	show_role(roles,num);
	return 0;
}

