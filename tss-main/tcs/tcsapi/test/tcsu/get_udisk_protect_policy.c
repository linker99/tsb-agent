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
#include "tcs_udisk_protect.h"
#include "tcs_udisk_protect_def.h"


	




void show_udisk_protect_policy(struct udisk_conf_item *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
				
		printf ("policy[%d] access_ctrl: %s\n",i, policy[i].access_ctrl == 1 ? "READ_ONLY" : "WRITE_ONLY");
		printf ("policy[%d] policy[i].access_ctrl: %d\n",i,policy[i].access_ctrl);
		printf ("policy[%d] ntohl(policy[i].access_ctrl): %d\n",i,ntohl(policy[i].access_ctrl));
		printf ("policy[%d] guid: %s\n",i,policy[i].guid);
	
		printf("\n\n");
	}
}
int main(int argc,char **argv){

	int ret = 0;
	int length = 0;
	int num = 0;
	struct udisk_conf_item *policy = NULL;

	ret = tcs_get_udisk_protect_policy(&policy,&num ,&length);
	
	if(ret){
		printf("[Error] tcs_get_udisk_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	
	show_udisk_protect_policy(policy, num);
	return 0;
}

