#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_dmeasure_def.h"

enum{
	PROCESS_DMEASURE_OBJECT_ID_FULL_PATH,//全路劲
	PROCESS_DMEASURE_OBJECT_ID_PROCESS,//进程名
	PROCESS_DMEASURE_OBJECT_ID_HASH,//HASH
};

enum{
	PROCESS_DMEASURE_MODE_DEFAULT,//默认（按全局策略控制）
	PROCESS_DMEASURE_MODE_MEASURE,//度量
	PROCESS_DMEASURE_MODE_NON_MEASURE,//不度量
};

#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	char buf[1024] = {0};
	char *full_path = "/mnt/hgfs/work/BASE_TSB/trunk/src/dmeasure_test/dm_task_test/printname";
	//char *full_path = "/mnt/hgfs/work/BASE_TSB/trunk/src/dmeasure_test/dm_task_test/printname_exec";

	struct dmeasure_process_item *p_dmeasure_process_policy= (struct dmeasure_process_item *)buf;
	p_dmeasure_process_policy->object_id_type = PROCESS_DMEASURE_OBJECT_ID_FULL_PATH;
	p_dmeasure_process_policy->sub_process_mode = PROCESS_DMEASURE_MODE_MEASURE;
	p_dmeasure_process_policy->old_process_mode = PROCESS_DMEASURE_MODE_MEASURE;
	p_dmeasure_process_policy->share_lib_mode = PROCESS_DMEASURE_MODE_MEASURE;
	p_dmeasure_process_policy->be_measure_interval = htonl(10000);
	p_dmeasure_process_policy->be_object_id_length = htons(strlen(full_path)+1);
	strcpy(p_dmeasure_process_policy->object_id, full_path);

	int len = sizeof(struct dmeasure_process_item) + strlen(full_path) + 1;
	BYTE4_ALIGNMENT(len);

	if (strcmp(argv[1], "1") == 0)
		tsb_add_process_dmeasure_policy((unsigned char *)p_dmeasure_process_policy, len);
	else if (strcmp(argv[1], "2") == 0)
		tsb_remove_process_dmeasure_policy((unsigned char *)p_dmeasure_process_policy, len);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_process_dmeasure_policy();
	else
		printf("param argv error!\n");
	
	return 0;
}
