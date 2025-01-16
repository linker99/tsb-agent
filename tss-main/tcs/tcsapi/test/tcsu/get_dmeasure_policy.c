#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "mem.h"
#include "tcs_dmeasure.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./get_dmeasure_policy\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int size = 0;
	struct  dmeasure_policy_item *policy = NULL;
	ret = tcs_get_dmeasure_policy (&policy, &num, &size);
	if (ret){
		printf ("[tcs_get_dmeasure_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		printf ("\n");
		printf ("item index: %d\n", i);
		printf ("[%d].be_type: %u\n", i, ntohl (policy[i].be_type));
		printf ("[%d].be_interval_milli: %u\n", i, ntohl(policy[i].be_interval_milli));
		printf ("[%d].object: %s\n", i, policy[i].object);
	}
	printf ("\n");
	
	if (policy)	httc_free (policy);
	return 0;
}



