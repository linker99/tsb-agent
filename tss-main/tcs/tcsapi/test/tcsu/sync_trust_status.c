#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#include "tcs_attest.h"

int tcs_sync_trust_status (uint32_t type);

enum{
 dmeasure = 0,
 imeasure, 
};

int main(int argc,char **argv)
{
	int ret = 0;
	uint32_t type = atoi(argv[1]);
	
	if((ret = tcs_sync_trust_status(type)) == 0) {
		printf("[tcs_sync_trust_status]\n");
	}
	else {
		printf("[tcs_sync_trust_status] ret: 0x%08x\n", ret);
		return -1;
	}

	return 0;
}





