#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "tpcm_command.h"
#include "tcs_error.h"

#include "tcs_license.h"
#include "tcs_attest.h"

int test_reset_test_license(void)
{
	int ret = 0;

	ret = tcs_reset_test_license();
	if(ret) {
		printf("[%s:%d]ret: 0x%08x\n", __func__, __LINE__, ret);
		return -1;
	}

	return 0;
}


int main(void)
{
	int ret = 0;

	if((ret = test_reset_test_license()) != 0) {
		printf("test_reset_test_license, ret = %d\n", ret);
		return -1;
	}
	else {
		printf("test_reset_test_license OK\n");
	}

	return 0;
}


