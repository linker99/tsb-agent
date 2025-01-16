#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tcs_maintain.h"



int main(void)
{
	int ret = 0;
	uint32_t status;
	
	if((ret = tcs_get_linked_switch_status(&status)) == 0) {

		printf("[tcs_get_linked_switch_status] status: %d\n", status);		
	}
	else {
		printf("[tcs_get_linked_switch_status] ret: 0x%08x\n", ret);
		return -1;
	}

	return 0;
}

