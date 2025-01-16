#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tcs_attest.h"

int main(void)
{
	int ret = 0;
	uint32_t feature;
	
	ret = tcs_get_tpcm_features(&feature);
	if(ret) {
		printf("[tcs_get_tpcm_features] ret: 0x%08x\n", ret);
		return -1;
	}
	
	printf("imeasure:%s\n", feature & 1 ? "YES":"NO");
	printf("dmeasure:%s\n", feature >> 1 & 1 ? "YES":"NO");
	printf("simple_boot:%s\n", feature >> 2 & 1 ? "YES":"NO");
	printf("bios_result:%s\n", feature >> 3 & 1 ? "YES":"NO");
	printf("support_upgrade:%s\n", feature >> 4 & 1 ? "YES":"NO");
	printf("flash_access:%s\n", feature >> 5 & 1 ? "YES":"NO");
	printf("simple imeasure: %s\n", feature >> 6 & 1 ? "YES":"NO");

	return 0;
}

