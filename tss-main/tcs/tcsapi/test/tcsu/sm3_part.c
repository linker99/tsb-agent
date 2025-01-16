#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>


#include "tcs_sm.h"
#include "tcs_constant.h"
#include "crypto/sm/sm3.h"
#include "crypto/sm/sm2_if.h"
#include "mem.h"
#include "debug.h"
#include "convert.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./sm3_part -s <hex-size>\n"
			"        -s <hex-size>      - the hex-size(Bytes) of data to SM3\n"
			"    eg. ./sm3_part -s 0x1000\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	int i = 0;
	void* ctx = NULL;
	uint32_t olen = 0;
	uint8_t *data = NULL;
	uint32_t dataLen = 0;
	uint32_t reseLen = 0;
	uint32_t curLen = 0;
	uint32_t opt = 0;
	SM3_DIGEST output = {0};
	SM3_DIGEST soft_output = {0};
	
	while ((ch = getopt(argc, argv, "s:t:h")) != -1)
	{
		switch (ch)
		{
			case 's':
				reseLen = dataLen = strtol (optarg, NULL, 16);
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}

	if(!dataLen){
		usage ();
		return -1;
	}

	if (NULL == (data = httc_malloc (dataLen))){
		httc_util_pr_error ("Malloc for data error, size = %d\n", dataLen);
		return -1;
	}
	memset (data, 0x12, dataLen);

	if (0 != (ret = tcs_sm3_init (&ctx))){
		httc_util_pr_error ("tcs_sm3_init error: %d\n", ret);
		httc_free (data);
		return -1;
	}

	do {
		curLen = MIN(reseLen, SM3_UPDATE_SIZE_LIMIT);
		if (0 != (ret = tcs_sm3_update (ctx, data+opt, curLen))){
			httc_util_pr_error ("tcs_sm3_update error: %d\n", ret);
			httc_free (data);
			return -1;
		}
		opt += curLen;
		reseLen -= curLen;
	}while (reseLen);
	
	if (0 != (ret = tcs_sm3_finish (ctx, output))){
		httc_util_pr_error ("tcs_sm3_finish error: %d\n", ret);
		httc_free (data);
		return -1;
	}

	sm3 (data, dataLen, soft_output);
	if (memcmp (output, soft_output, DEFAULT_HASH_SIZE)){
		httc_util_pr_error ("Incorrect digest result!\n");
        httc_util_dump_hex("hard hash", output, DEFAULT_HASH_SIZE);
        httc_util_dump_hex("soft hash", soft_output, DEFAULT_HASH_SIZE);
		httc_free (data);
		return -1;
	}

	httc_util_dump_hex("hard hash", output, DEFAULT_HASH_SIZE);

	httc_free (data);
	return ret;	
}


