#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "httcutils/mem.h"
#include "httcutils/debug.h"
#include "tcsapi/tcs_constant.h"
#include "tcsapi/tcs_dev_protect.h"
#include "tcsapi/tcs_dev_protect_def.h"
#include "tcfapi/tcf_dev_protect.h"


#if 1
void show_cdrom_protect_policy(struct cdrom_protect_item *policy,int num){

	int i = 0;
	
	for(;i < num; i++){
		printf("RUN:%d\n",i);
		printf ("policy[%d] measure_flags: %s\n",i, policy[i].be_flags == 1 ? "CDROM_PROTECT" : "CDROM_NO_PROTECT");
		printf(" policy[i].be_flags:%d\n", policy[i].be_flags);
		printf("\n\n");
	}
}

int main(int argc,char **argv){

	int ret = 0;
	int num = 0;
	struct cdrom_protect_item *policy = NULL;

	ret = tcf_get_cdrom_protect_policy(&policy,&num);
	if(ret){
		printf("[Error] tcs_get_tnc_policy ret:0x%08X\n",ret);
		if(policy) httc_free(policy);
		return -1;
	}
	show_cdrom_protect_policy(policy, num);
	return 0;
}
#endif
