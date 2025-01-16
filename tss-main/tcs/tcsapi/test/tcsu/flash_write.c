#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "debug.h"
#include "tcs_tpcm.h"

void usage (void)
{
		printf ("\n");
		printf (" Usage: ./flash_write ZOON OFFSET SIZE DATA\n");
		printf ("    eg. ./flash_write 0x1 0x10000 0x20 helloworld\n");
		printf ("\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint32_t offset = 0;
	uint32_t zoon = 0;
	uint32_t size = 0;
	uint8_t *data = NULL;

	if (argc != 5){
		usage();
		return -EINVAL;
	}
	
	zoon = strtol (argv[1], NULL, 16);
	offset = strtol (argv[2], NULL, 16);
	size = strtol (argv[3], NULL, 16);
	data = argv[4];

	httc_util_dump_hex ("Flash write", data, size);
	ret = tcs_flash_write (zoon, offset, size, data, &tpcmRes);
	if (ret || tpcmRes){
		printf ("[tcs_flash_write]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		return -1;
	}
	
	return 0;
}

