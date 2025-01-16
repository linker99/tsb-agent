#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include <httcutils/mem.h>
#include "tcfapi/tcf_dmeasure.h"
#include "tcsapi/tcs_policy_def.h"

int main ()
{
	int i = 0;
	int ret = 0;
	int num = 0;
	struct dmeasure_process_item_user *policy = NULL;

	if (0 != (ret = tcf_get_dmeasure_process_policy (&policy, &num))){
		httc_util_pr_error ("tcf_get_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	for (i = 0; i < num; i++){
		printf ("\n");
		printf ("dm_policy index: %d\n", i);
		printf ("[%d].object_id_type: %d\n", i, policy[i].object_id_type);
		printf ("[%d].sub_process_mode: %d\n", i, policy[i].sub_process_mode);
		printf ("[%d].old_process_mode: %d\n", i, policy[i].old_process_mode);
		printf ("[%d].share_lib_mode: %d\n", i, policy[i].share_lib_mode);
		printf ("[%d].measure_interval: %d\n", i, policy[i].measure_interval);
		printf ("[%d].object_id_length: %d\n", i, policy[i].object_id_length);
		if (PROCESS_DMEASURE_OBJECT_ID_HASH == policy[i].object_id_type){
			printf ("[%d].", i); httc_util_dump_hex ("object_id", policy[i].object_id, policy[i].object_id_length);
		}else
			printf ("[%d].object_id: %s\n", i, policy[i].object_id);
	}	
	printf ("\n");

	if (policy)	tcf_free_dmeasure_process_policy (policy, num);
	return 0;
}

