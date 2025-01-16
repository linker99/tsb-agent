#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "httcutils/mem.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_network_control.h"
#include "tcsapi/tcs_network_control_def.h"
#include "tcfapi/tcf_network_control.h"

void show_network_control_policy(struct network_config_item_user *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
		printf ("policy[%d] port_sw: %s\n",i, policy[i].port_sw == 1 ? "NETWORK_SWITCH_OPEN" : "NETWORK_SWITCH_OFF");
		printf ("policy[%d] total_num: %d\n",i, policy[i].total_num);	
		for(j = 0 ;j < policy[i].total_num; j++){
			printf ("[%d] policy[i].item from: %d\n",j, policy[i].item[j]->from);
			printf ("[%d] policy[i].item id: %d\n",j, policy[i].item[j]->id);
			printf ("[%d] policy[i].item status: %d\n",j, policy[i].item[j]->status);
			printf ("[%d] policy[i].item to: %d\n",j, policy[i].item[j]->to);
			
			
		}
		printf("\n\n");
	}
	if(policy) tcf_free_network_control_policy(policy,num);
}


int main(int argc,char **argv){

	int ret = 0;
	int num = 0;
	 struct network_config_item_user *policy = NULL;

	ret = tcf_get_network_control_policy(&policy,&num);
	if(ret){
		printf("[Error] tcf_get_network_control_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_network_control_policy(policy, num);
	return 0;
}
