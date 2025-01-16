#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <httcutils/debug.h>
#include "tcfapi/tcf_attest.h"

int main(void)
{
	int ret = 0;
	uint8_t id[128] = {0};
	uint32_t id_len = sizeof(id);

	ret = tcf_get_tpcm_id(id, &id_len);
	if(ret) {
		printf("[tcf_get_tpcm_id] ret: 0x%08x\n", ret);
		return -1;
	}
	printf("\n");
	httc_util_dump_hex("TPCM ID", id, id_len);
	printf("\n");
	
	return 0;
}
