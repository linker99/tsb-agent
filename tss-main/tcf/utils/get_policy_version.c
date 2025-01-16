#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcfapi/tcf_attest.h"
#include "tcsapi/tcs_attest_def.h"

void show_policies_version(void){
	printf("0:	管理认证策略\n");
	printf("1:	全局策略\n");
	printf("2:	启动度量基准值\n");
	printf("3:	动态度量策略\n");
	printf("4:	进程动态度量\n");
	printf("5:	白名单\n");
	printf("6:	进程身份\n");
	printf("7:	进程角色\n");
	printf("8:	进程跟踪\n");
	printf("9:	可信连接\n");
	printf("10:	密钥树\n");
	printf("11:	存储管理\n");
	printf("12:	审计策略\n");
	printf("13:	通知缓存\n");
	printf("14:	关键文件\n");
	
}

int main(void){
	int i = 0;
	int ret = 0;
	int number = 20;
	struct policy_version_user ver[20];
	
	ret = tcf_get_policies_version(ver, &number);
	if(ret){
		printf("[Error] tcf_get_policies_version ret:0x%08X\n",ret);
		return -1;
	}
	printf("\n");
	show_policies_version();
	printf("\n");
	for(; i < number; i++){
		printf("type:%d major:0x%016lX minor:0x%08X\n",ver[i].type,ver[i].major,ver[i].minor);
	}
	printf("\n");
	return ret;
}

