#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_attest.h"

int main(void)
{
	int ret = 0;

	uint8_t *id = "67c6697351ff4aec29cdbaabf2fbe346";
	int len = 32;

	ret = tcf_set_host_id(id, len);
	if(ret) {
		printf("[tcf_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	
	return 0;
}
