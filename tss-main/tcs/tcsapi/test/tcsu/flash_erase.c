#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "tcs_tpcm.h"

void usage (void)
{
		printf ("\n");
		printf (" Usage: ./flash_erase ZOON OFFSET SIZE\n");
		printf ("    eg. ./flash_erase 0x1 0x10000 0x20\n");
		printf ("\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint32_t zoon = 0;
	uint32_t offset = 0;
	uint32_t size = 0;

	if (argc != 4){
		usage();
		return -EINVAL;
	}
	
	zoon = strtol (argv[1], NULL, 16);
	offset = strtol (argv[2], NULL, 16);
	size = strtol (argv[3], NULL, 16);

	ret = tcs_flash_erase (zoon, offset, size, &tpcmRes);
	if (ret || tpcmRes){
		printf ("[tcs_flash_erase]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		return -1;
	}
	
	return 0;
}


