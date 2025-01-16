#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tcs_maintain.h"



int main(void)
{
	int ret = 0;
	
	ret = tcs_clear_linked_switch_status();
	printf("[tcs_clear_linked_switch_status] ret: 0x%08x\n", ret);
	
	return ret ? -1 : 0;
}

