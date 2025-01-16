#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void usage ()
{
	printf ("\n"
			" Usage: ./get_one_ploicy_cersion [options]\n"
			" options:\n"
			"        -p <policy>           - The policy tag\n"
			"    eg. ./get_one_ploicy_cersion -p 0\n"
			"\n");
	show_policies_version();
}

int main(int argc,char **argv){

	int i = 0;
	int ch = 0;
	int ret = 0;
	
	struct policy_version_user version;
	

	if(argc != 3){
		usage();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "p:")) != -1)
	{
		switch (ch) 
		{
			case 'p':
				version.type = atoi(optarg);
				break;
			default:
				usage ();
				return -1;
		}
	}
	
	ret = tcf_get_one_policy_version(&version);		
	if(ret){
		printf("[Error] tcf_get_one_policy_version ret:0x%08X\n",ret);
		return -1;
	}
	show_policies_version();
	printf("\ntype:%d major:0x%016lX minor:0x%08X\n",version.type,version.major,version.minor);

	return 0;
}
