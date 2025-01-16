#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include "httcutils/sys.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include "tcfapi/tcf_store.h"

static void show_nv_list(struct nv_info *infos,int number){

	int i = 0;
//	httc_util_dump_hex((const char *)"nv list", infos, 1000);
	for(i = 0; i < number;i++){
		printf("---------------cycle:%d----------\n",i);
		printf("index:%d\n",infos[i].index);
		printf("name:%s\n",infos[i].name);
		printf("size:%d\n",infos[i].size);
		printf("policy->flags:0x%08X\n",infos[i].auth_policy.policy_flags);
		printf("policy->process_or_role:%s\n",infos[i].auth_policy.process_or_role);
		printf("policy->user_or_group:%d\n",infos[i].auth_policy.user_or_group);		
	} 
}

int main(int argc, char **argv){

	int ret = 0;
	struct nv_info *infos = NULL;
	const char *file = "nvinfos";
	int number = 0;
	char com[128];
	ret = tcf_read_nv_list(&infos,&number);
	if(ret){
		printf("tcf_read_nv_list fail! ret:0x%08X!\n",ret);
		return -1;
	}
	show_nv_list(infos,number);
	
	sprintf(com,"echo %d > number.txt",number);
	ret = httc_util_system((const char *)com);

	tcf_free_nv_list(infos,number);
	return 0;
}




