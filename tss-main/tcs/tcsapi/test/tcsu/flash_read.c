#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "mem.h"
#include "debug.h"
#include "tcs_tpcm.h"

void usage (void)
{
		printf ("\n");
		printf (" Usage: ./flash_read ZOON OFFSET SIZE\n");
		printf ("    eg. ./flash_read 0x1 0x10000 0x20\n");
		printf ("\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	uint32_t zoon = 0;
	uint32_t offset = 0;
	uint32_t size = 0;
	uint8_t *data = NULL;

	if (argc != 4){
		usage();
		return -EINVAL;
	}
	
	zoon = strtol (argv[1], NULL, 16);
	offset = strtol (argv[2], NULL, 16);
	size = strtol (argv[3], NULL, 16);

	if (NULL == (data = httc_malloc (size + 1))){
		perror ("Malloc error");
		return -ENOMEM;
	}
		
	ret = tcs_flash_read (zoon, offset, size, data, &tpcmRes);
	if (!ret && !tpcmRes)
		httc_util_dump_hex ("Flash read", data, size);
	else{
		printf ("[tcs_flash_read]ret: 0x%08x, tpcmRes: 0x%08x\n", ret, tpcmRes);
		ret = -1;
	}

	httc_free (data);
	return ret;
}

