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
#include "debug.h"

#define SM_CHECK

static void usage ()
{
	printf ("\n"
			" Usage: ./sm2_speed [ -t <times> ]\n"
			"        -t <times>         - the times of test sm3 <default: 1>"
			"    eg. ./sm2_speed -t 100\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	int i = 0;
	int cycle = 1;
	struct timeval start;
	struct timeval end;
	uint64_t used_usec = 0;
	float used_sec = 0;
	uint8_t  data[128] = {0};
	uint32_t dataLen = sizeof (data);
	uint8_t sig[64] = {0};
	uint32_t sigLen = sizeof (sig);
	unsigned char *privkey = NULL;
	unsigned int privkey_len = 0;
	unsigned char *pubkey = NULL;
	unsigned int pubkey_len = 0;
	sm3_context ctx;
	uint8_t Z[DEFAULT_HASH_SIZE] = {0};
	uint8_t E[DEFAULT_HASH_SIZE] = {0};
	uint32_t digest_len = sizeof(E);
	unsigned char *ID = "1234567812345678";
	
	while ((ch = getopt(argc, argv, "t:h")) != -1)
	{
		switch (ch)
		{
			case 't':
				cycle = atoi (optarg);
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}

	memset (data, 0x12, dataLen);

	if (0 != (ret = os_sm2_generate_key (&privkey, &privkey_len, &pubkey, &pubkey_len))){
		printf ("generate sign key error: %d\n", ret);
		return -1;
	}
	os_generate_param_z (pubkey, pubkey_len, ID, strlen (ID), Z);
	sm3_init (&ctx);
	sm3_update (&ctx, Z, sizeof (Z));
	sm3_update (&ctx, data, dataLen);
	sm3_finish (&ctx, E);

	/** Sign rate test */
	gettimeofday (&start, NULL);
	for (i = 0; i < cycle; i ++){
		if (0 != (ret = tcs_sm2_sign(privkey, E,  digest_len, sig, &sigLen))){
			printf ("tpcm_sign_e error: %d\n", ret);
			return -1;
		}
	}
	gettimeofday (&end, NULL);

	used_usec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	used_sec = used_usec / (float)1000000;
	printf ("  SM2 sign speed  >>>  |times: %-8d |rate(times/s): %.02f\n", cycle, (float)cycle/used_sec);


       //httc_util_dump_hex("SM2", sig, sigLen);

#ifdef SM_CHECK
	/** Check whether sign|verify is correct */
	if (0 !=  tcs_sm2_verify (pubkey, E,  digest_len, sig, sigLen)){
		printf ("SM2 Verify failed\n");
		return -1;
	}
#endif



	return ret;	
}


