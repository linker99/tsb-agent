#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "tcs_attest.h"
#include "tcs_attest_def.h"


int main(void)
{
	int i = 0;
	int ret = 0;
	int num = 15;
	struct policy_version policies[POLICIES_TYPE_MAX];
	
	ret = tcs_get_policies_version(policies,&num);
	printf("num:%d\r\n",num);
	if(ret) {
		printf("[tcs_get_policies_version] ret: 0x%08x\n", ret);
		return -1;
	}
	
	for(;i < num; i++){
		printf("%d : 0x%016lX\n", ntohl(policies[i].be_policy), ntohll(policies[i].be_version));
	}
	
	return 0;
}

