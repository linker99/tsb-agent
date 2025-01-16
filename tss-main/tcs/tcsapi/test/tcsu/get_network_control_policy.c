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
#include "tcs_network_control.h"
#include "tcs_network_control_def.h"


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0],\
	((unsigned char *)&addr)[1],\
	((unsigned char *)&addr)[2],\
	((unsigned char *)&addr)[3]
	


void show_network_control_policy(struct network_config_item *policies, int length ,int num){

	int i = 0;
	int j = 0;
	int op = 0;
	int opt = 0;
	int number = 0;
	struct network_config_item *cur_item = NULL;
	struct ip_config *cur = NULL;

 	for (j = 0 ; j < num; j++){
		cur_item = (struct network_config_item *)((uint8_t *)policies + op);
		printf ("policies->be_port_sw: %s\n", cur_item->be_port_sw == 1 ? "NETWORK_SWITCH_OPEN" : "NETWORK_SWITCH_OFF");
		printf ("policies->be_total_num: %d\n", ntohl (cur_item->be_total_num));
	
		number = (int)ntohl(cur_item->be_total_num);
		opt = 0;	
		for(i = 0;i < number; i++){
			cur = (struct ip_config *)((uint8_t *)cur_item->item + opt);
			printf ("be_from: %d\n",  (cur->be_from));
			printf ("be_to: %d\n",  (cur->be_to));
			printf ("be_id: %d\n",  (cur->be_id));
			printf ("be_status: %d\n", (cur->be_status));	
		
			printf("\n\n");
			opt += sizeof(struct ip_config);			
		}

		op += opt;
		op += sizeof(struct network_config_item);
		HTTC_ALIGN_SIZE(op,4);
		
		if(op > length) break;
	}
	
	if(policies) httc_free(policies);
}

int main(int argc,char **argv){

	int ret = 0;
	int length = 0;
	int num = 0;
	struct network_config_item *policy = NULL;

	ret = tcs_get_network_control_policy(&policy,&num ,&length);
	if(ret){
		printf("[Error] tcs_get_network_control_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_network_control_policy(policy, length , num);
	return 0;
}

