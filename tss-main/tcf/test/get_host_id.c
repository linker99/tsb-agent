#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_attest.h"

int main(void)
{
	int ret = 0;
	uint8_t id[32] = {0};
	uint32_t id_len = sizeof(id);

	ret = tcf_get_host_id(id, &id_len);
	if(ret) {
		printf("[tcf_get_host_id] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex("host_id", id, id_len);

	return 0;
}

