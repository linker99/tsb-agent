#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "tcs_attest.h"

int main(void)
{
	int ret = 0;
	uint8_t id[128] = {0};
	uint32_t id_len = sizeof(id);

	ret = tcs_get_tpcm_id(id, &id_len);
	if(ret) {
		printf("[tcs_get_tpcm_id] ret: 0x%08x\n", ret);
		return -1;
	}
	printf("\n");
	httc_util_dump_hex("TPCM ID", id, id_len);
	printf("\n");
	
	return 0;
}

