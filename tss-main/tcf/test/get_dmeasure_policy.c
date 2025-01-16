#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/mem.h>
#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_dmeasure.h"

int main ()
{
	int i = 0;
	int ret = 0;
	int num = 0;
	struct dmeasure_policy_item_user *policy = NULL;

	if (0 != (ret = tcf_get_dmeasure_policy (&policy, &num))){
		httc_util_pr_error ("tcf_get_dmeasure_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	for (i = 0; i < num; i++){
		printf ("\n");
		printf ("dm_policy index: %d\n", i);
		printf ("[%d].name: %s\n", i, policy[i].name);
		printf ("[%d].type: %u\n", i, policy[i].type);
		printf ("[%d].interval_milli: %u\n", i, policy[i].interval_milli);
	}	
	printf ("\n");

	if (policy)	tcf_free_dmeasure_policy (policy, num);
	return 0;
}

