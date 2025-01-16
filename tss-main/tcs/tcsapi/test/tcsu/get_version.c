#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "tcs_tpcm.h"

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint8_t version[128] = {0};
	uint32_t length = sizeof (version);

	ret = tcs_get_version (&length, version, &tpcmRes);
	if (ret || tpcmRes){
		printf ("[tcs_get_version]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		return -1;
	}
	httc_util_dump_hex ("version", version, length);
	
	return 0;
}

