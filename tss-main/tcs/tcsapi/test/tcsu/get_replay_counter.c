#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcs_attest.h"

int main(void)
{
	int ret = 0;
	uint64_t replay_counter = 0;
	
	ret = tcs_get_replay_counter (&replay_counter);
	if(ret) {
		printf("[tcs_get_replay_counter] ret: 0x%08x\n", ret);
		return -1;
	}
	printf("replay_counter: %ld(0x%lx)\n", replay_counter, replay_counter);
	return 0;
}

