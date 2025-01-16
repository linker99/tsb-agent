#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "tcmutil.h"
#include "tcmfunc.h"
#include "mem.h"
#include "tcs_sm.h"
#include "debug.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./sm_get_random -s <hex-size> ]\n"
			"        -s <hex-size>      - the hex-size(Bytes) of data to encrypt|decrypt\n"
			"    eg. ./sm_get_random -s 0x1000\n");
}		

int main(int argc, char **argv)
{
	unsigned char *buffer = NULL;
	uint32_t size = 0;
	uint32_t ret = 0;
	int ch ;

	while ((ch = getopt(argc, argv, "s:h")) != -1)
	{
		switch (ch)
		{
			case 's':
				size  = strtol (optarg, NULL, 16);
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}
	if(!size){
		usage ();
		return -1;
	}
	buffer = httc_malloc(size);
	if(buffer == NULL){
		printf("random malloc buffer error\n");
		return -1;
	}
	memset(buffer, 0, size);
	ret = tcs_random (buffer, size);
	if(ret != 0){
		printf("tcs get random error %d\n", ret);
		httc_free(buffer);
		return -1;
	}
	httc_util_dump_hex("tcs random data : ",  buffer, size);

	httc_free(buffer);
	return 0;
}
