#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/convert.h>
#include <httcutils/debug.h>
#include "tcfapi/tcf_protect.h"

int main ()
{
	int i = 0;
	int ret = 0;
	int num = 0;
	struct ptrace_protect_user *policy = NULL;

	if (0 != (ret = tcf_get_ptrace_protect_policy  (&policy))){
		httc_util_pr_error ("tcf_get_dmeasure_process_policy error: %d(0x%x)\n", ret, ret);
		return ret;
	}

	if (policy){
		printf ("\n");
		printf ("PTRACE PROTECT\n");
		printf ("  is_ptrace_protect: %d\n", policy->is_ptrace_protect);
		printf ("  ptracer_number: %u\n", policy->ptracer_number);
		printf ("  non_tracee_number: %u\n", policy->non_tracee_number);
		printf ("   ptracer process:\n");
		for (i = 0; i < policy->ptracer_number; i++)
			printf ("    [%d] %s\n", i, policy->ptracer_names[i]);
		printf ("  non tracee process:\n");
		for (i = 0; i < policy->non_tracee_number; i++)
			printf ("    [%d] %s\n", i, policy->non_tracee_names[i]);
		printf ("\n");	

		tcf_free_ptrace_protect_policy (policy);
	}

	return 0;
}

