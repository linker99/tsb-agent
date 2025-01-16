#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "httcutils/mem.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_file_protect.h"
#include "tcsapi/tcs_file_protect_def.h"
#include "tcfapi/tcf_file_protect.h"


void show_file_protect_policy(struct file_protect_item_user *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
		printf ("policies[%d] is_default_policy: %s\n",i, (policy[i].measure_flags & 0x80) ? "YES" : "NO");
		printf ("policy[%d] measure_flags: %s\n",i, (policy[i].measure_flags & 0x7F) == 1 ? "FILE_PROTECT_MEASURE_ENV" : "FILE_PROTECT_MEASURE_PROCESS");
		printf ("policy[%d] type: %s\n",i, policy[i].type == 0 ? "FILE_WRITE_PROTECT" : "FILE_READ_PROTECT");
		printf ("policy[%d] path: %s\n",i, policy[i].path);
		printf ("policy[%d] privileged_process_num: %d\n",i, policy[i].privileged_process_num);
		
		for(j = 0 ;j < policy[i].privileged_process_num; j++){
			printf ("[%d] file_protect_privileged_process_user privi_type: %s\n",j, 
						policy[i].privileged_processes[j]->privi_type == 0 ? "PRIVI_ALL" : "PRIVI_READ_ONLY");
			printf ("[%d] file_protect_privileged_process_user path: %s\n",j, policy[i].privileged_processes[j]->path);

			httc_util_dump_hex("hash",policy[i].privileged_processes[j]->hash,32);
			printf("\n\n");
			
		}
		printf("\n\n");
	}
	if(policy) tcf_free_file_protect_policy(policy,num);
}


int main(int argc,char **argv){

	int ret = 0;
	int num = 0;
	struct file_protect_item_user *policy = NULL;

	ret = tcf_get_file_protect_policy(&policy,&num);
	if(ret){
		printf("[Error] tcs_get_tnc_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_file_protect_policy(policy, num);
	return 0;
}
