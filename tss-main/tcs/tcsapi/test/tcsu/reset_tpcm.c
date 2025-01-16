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

extern int tcs_reset_tpcm(void);

int main()
{
	int ret = 0;

	ret = tcs_reset_tpcm();
	if(ret != 0){
		printf("tcs_reset_tpcm : ret = %d\n", ret);
		return -1;
	}
	printf(" tcs_reset_tpcm is OK\n");

	return ret;
}

