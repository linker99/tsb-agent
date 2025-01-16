#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_license.h"



int main()
{
	int ret = 0;
	ret = tcf_reset_test_license();
	if(ret != 0){
		printf("tcf reset test license error\n");
		return -1;
	}else{
		printf(" tcf reset test license OK\n");
	}

	return ret;
}
