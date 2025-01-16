#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "httcutils/mem.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_udisk_protect.h"
#include "tcsapi/tcs_udisk_protect_def.h"
#include "tcfapi/tcf_udisk_protect.h"



void show_udisk_protect_policy(struct udisk_conf_item *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
				
		printf ("policy[%d] access_ctrl: %s\n",i, policy[i].access_ctrl == 1 ? "READ_ONLY" : "WRITE_ONLY");
		printf ("policy[%d] access_ctrl: %d\n",i,policy[i].access_ctrl);
		
	
		printf("\n\n");
	}
}

int main(int argc,char **argv){

	int ret = 0;
	int num = 0;
	struct udisk_conf_item *policy = NULL;

	ret = tcf_get_udisk_protect_policy(&policy,&num);
	if(ret){
		printf("[Error] tcs_get_udisk_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_udisk_protect_policy(policy, num);
	return 0;
}

