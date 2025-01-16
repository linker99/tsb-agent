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
#include "tcs_dev_protect.h"
#include "tcs_dev_protect_def.h"


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0],\
	((unsigned char *)&addr)[1],\
	((unsigned char *)&addr)[2],\
	((unsigned char *)&addr)[3]
	




void show_cdrom_protect_policy(struct cdrom_protect_item *policy,int num){

	int i = 0;
	int j = 0;
	for(;i < num; i++){
		printf("RUN:%d\n",i);
		printf ("policy[%d] be_flags: %s\n",i, (policy[i].be_flags) == 1 ? "CDROM_PROTECT" : "CDROM_NO_PROTECT");
		printf(" policy[%d] ntohl be_flags::%d\n",i,ntohl(policy[i].be_flags));
		printf("\n\n");
	}
}
int main(int argc,char **argv){

	int ret = 0;
	int length = 0;
	int num = 0;
	struct cdrom_protect_item *policy = NULL;

	ret = tcs_get_cdrom_protect_policy(&policy,&num ,&length);
	if(ret){
		printf("[Error] tcs_get_tnc_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_cdrom_protect_policy(policy, num);
	return 0;
}

