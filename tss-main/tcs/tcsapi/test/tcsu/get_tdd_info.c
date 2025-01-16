#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"

const char * g_tdd_desc[TDD_TYPE_MAX] = {"SIMULATOR", "3310", "PK", "GOKE", "HYGON", "TSINGHUA", "CC903TM", "QEMU", "MAIPU", "PANTUM", "TSINGHUA_NEW"};

int main(void)
{
	int ret = 0;
	struct tdd_info td_info;

	if(0 != (ret = tcs_get_tdd_info(&td_info))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf("Tdd info :\n");
	printf("tdd_type : %d\n", ntohl(td_info.be_tdd_type));
	printf("tdd_type : %s\n", g_tdd_desc[ntohl(td_info.be_tdd_type)]);
	printf("\n");
	
	return 0;
}


