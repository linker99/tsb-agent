#include <stdio.h>
#include <stdint.h>

#include "tcfapi/tcf_file_integrity.h"
#include <httcutils/debug.h>

int main(void)
{
	int ret = 0;
	uint8_t digest[32] = {0};
	uint32_t digest_len = 32;
	ret = tcf_get_critical_file_integrity_digest (digest, &digest_len);
	if(ret) {
		printf("[tcs_get_critical_file_integrity_digest] ret: 0x%08x\n", ret);
		return -1;
	}
	httc_util_dump_hex("digest", digest, digest_len);

	return 0;
}

