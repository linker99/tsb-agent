#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "httcutils/debug.h"
#include "tcfapi/tcf_attest.h"

const char *status_desc[3] = {"trusted", "untrusted", "unknown"};

int main(void)
{
	int ret = 0;
	uint32_t status;
	
	if(0 != (ret = tcf_get_trust_status(&status))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	if ((status < STATUS_TRUSTED) || (status > STATUS_UNKNOWN)){
		httc_util_pr_error ("Invalid trust status: %d\n", status);
		return -1;
	}

	printf ("\n");
	printf ("Trust status: %s\n", status_desc[status]);
	printf ("\n");
	
	return 0;
}

