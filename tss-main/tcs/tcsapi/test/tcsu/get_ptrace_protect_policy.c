#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_dmeasure.h"
#include "tcs_protect.h"

int main (int argc, char **argv)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int ops = 0;
	int size = 0;
	struct ptrace_protect *policy = NULL;
	
	ret = tcs_get_ptrace_protect_policy ((struct ptrace_protect **)&policy, &size);
	if (ret){
		printf ("[tcs_get_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	if (policy){
		printf ("PTRACE PROTECT:\n");
		printf ("  total_length: %d\n", ntohl(policy->be_total_length));
		printf ("  ptrace_protect: %d\n", ntohl(policy->be_ptrace_protect));
		printf ("  ptracer_number: %d\n", ntohl(policy->be_ptracer_number));
		printf ("  non_tracee_number: %d\n", ntohl(policy->be_non_tracee_number));

		printf ("    ptracer process:\n");
		for (i = 0; i < ntohl(policy->be_ptracer_number); i++){
			ops += sizeof (struct process_name);
			printf ("    [%d] %s\n", i, policy->process_names + ops);
			ops += HTTC_ALIGN_SIZE (strlen (policy->process_names + ops) + 1, 4);
		}
		printf ("    non tracee process:\n");
		for (i = 0; i < ntohl(policy->be_non_tracee_number); i++){
			ops += sizeof (struct process_name);
			printf ("    [%d] %s\n", i, policy->process_names + ops);
			ops += HTTC_ALIGN_SIZE (strlen (policy->process_names + ops) + 1, 4);
		}
		printf ("\n");

		httc_free (policy);
	}

	return 0;
}

