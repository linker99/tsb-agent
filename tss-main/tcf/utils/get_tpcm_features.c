#include <stdio.h>
#include <stdint.h>

#include "httcutils/debug.h"
#include "tcfapi/tcf_attest.h"

int main(void)
{
	int ret = 0;
	uint32_t feature;
	
	ret = tcf_get_tpcm_features(&feature);
	if(ret) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf("\n");
	printf("TPCM features:\n");
	printf("  support intercept measure: %s\n", feature & (1 << TPCM_FEATURES_INTERCEPT_MEASURE) ? "YES":"NO");
	printf("  support dynamic measure: %s\n", feature & (1 << TPCM_FEATURES_DYNAMIC_MEASURE) ? "YES":"NO");
	printf("  support simple boot measure: %s\n", feature & (1 << TPCM_FEATURES_SIMPLE_BOOT_MEASURE) ? "YES":"NO");
	printf("  support import bios measure result: %s\n", feature & (1 << TPCM_FEATURES_IMPORT_BIOS_MEASURE_RESULT) ? "YES":"NO");
	printf("  support firmware upgrade: %s\n", feature & (1 << TPCM_FEATURES_FIRMWARE_UPGRADE) ? "YES":"NO");
	printf("  support flash access: %s\n", feature & (1 << TPCM_FEATURES_FLASH_ACCESS) ? "YES":"NO");
	printf("  support simple intercept measure: %s\n", feature & (1 << TPCM_FEATURES_SIMPLE_INTERCEPT_MEASURE) ? "YES":"NO");
	printf("\n");
	
	return 0;
}

