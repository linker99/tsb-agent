#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "httcutils/mem.h"
#include "httcutils/convert.h"
#include "tcsapi/tcs_constant.h"
#include "tcfapi/tcf_tnc.h"
#include "tcsapi/tcs_tnc_def.h"


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0],\
	((unsigned char *)&addr)[1],\
	((unsigned char *)&addr)[2],\
	((unsigned char *)&addr)[3]



void show_tnc_policy(struct tnc_policy *policies, int length){

	int i = 0;
	int num = 0;
	
	printf("================tnc_policy================\n");
	printf ("policies->server_ip: %d.%d.%d.%d\n", NIPQUAD(policies->be_server_ip));
	printf ("policies->server_port: %d\n", ntohs (policies->be_server_port));
	printf ("policies->control_mode: %s\n", ntohl (policies->be_control_mode) == 0 ? "UNCONTROL" : "CONTROL ALL");
	printf ("policies->encrypt_auth: %s\n", policies->encrypt_auth == 0 ? "NO" : "YES");
	printf ("policies->server_testify: %s\n", policies->server_testify == 0 ? "NO" : "YES");
	printf ("policies->report_auth_fail: %s\n", policies->report_auth_fail == 0 ? "NO" : "YES");
	printf ("policies->report_session: %s\n", policies->report_session == 0 ? "NO" : "YES");
	printf ("policies->be_session_expire: %d\n", ntohl (policies->be_session_expire));
	printf ("policies->be_exception_number: %d\n", ntohl(policies->be_exception_number));
	num = ntohl(policies->be_exception_number);
	
	for(;i < num; i++){
		printf("================tnc_policy_item:%d================\n",i);
		printf ("protocol: %s\n", ntohl(policies->exceptions[i].be_protocol) == 2 ? "UDP" : (ntohl(policies->exceptions[i].be_protocol) == 1 ? "TCP" : "UDP/TCP"));
		printf ("remote_ip: %d.%d.%d.%d\n", NIPQUAD(policies->exceptions[i].be_remote_ip));
		printf ("local_ip: %d.%d.%d.%d\n", NIPQUAD(policies->exceptions[i].be_local_ip));		
		printf ("remote_port: %d\n", ntohs (policies->exceptions[i].be_remote_port));
		printf ("local_port: %d\n", ntohs (policies->exceptions[i].be_local_port));		
	}
	if(policies) httc_free(policies);
}

int main(int argc,char **argv){

	int ret = 0;
	int length = 0;
	struct tnc_policy *policy = NULL;

	ret = tcf_get_tnc_policy(&policy,&length);
	if(ret){
		printf("[Error] tcs_get_tnc_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_tnc_policy(policy, length);
	return 0;
}
