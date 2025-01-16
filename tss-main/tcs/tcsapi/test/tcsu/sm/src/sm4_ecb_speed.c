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
#include "crypto/sm/sm4.h"
#include "crypto/sm/sm2_if.h"
#include "mem.h"
#include "debug.h"

//#define SM_CHECK

static void usage ()
{
	printf ("\n"
			" Usage: ./sm4_speed -s <hex-size> [ -t <times> ]\n"
			"        -m <mode>          - mode option\n"
			"        -s <hex-size>      - the hex-size(Bytes) of data to encrypt|decrypt\n"
			"        -t <times>         - the times of test sm3 <default: 1>"
			"    eg. \n"
			"        ./sm4_speed -s 0x1000 -t 100\n");
}

uint8_t  key[16] = {
				0x8c,0x20,0x8a,0xb7,0xc5,0x6b,0x63,0xec,
				0x8e,0x1e,0xdb,0x6a,0xd0,0xaf,0x75,0x7f};
				
int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	int i = 0;
	int cycle = 1;
	uint8_t *data = NULL;
	uint32_t dataLen = 0;
	uint8_t *enc = NULL;
	uint32_t encLen = 0;
	uint8_t *dec = NULL;
	uint32_t decLen = 0;
	uint8_t *soft_enc = NULL;
	uint32_t soft_encLen = 0;
	struct timeval start;
	struct timeval end;
	uint64_t used_usec = 0;
	float used_sec = 0;
	uint32_t mode = 0;
#ifdef SM_CHECK
	sm4_context ctx;
#endif

	while ((ch = getopt(argc, argv, "s:t:h")) != -1)
	{
		switch (ch)
		{
			case 's':
				dataLen = strtol (optarg, NULL, 16);
				soft_encLen = encLen = decLen = dataLen + 16;
				break;
			case 't':
				cycle = atoi (optarg);
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
		printf ("Malloc for data error, size = %d\n", dataLen);
		return -1;
	}
	if (NULL == (enc = httc_malloc (encLen))){
		printf ("Malloc for data error, size = %d\n", encLen);
		httc_free (data);
		return -1;
	}
	if (NULL == (dec = httc_malloc (decLen))){
		printf ("Malloc for data error, size = %d\n", decLen);
		httc_free (data);
		httc_free (enc);
		return -1;
	}
	if (NULL == (soft_enc = httc_malloc (soft_encLen))){
		printf ("Malloc for data error, size = %d\n", soft_encLen);
		httc_free (data);
		httc_free (enc);
		httc_free (dec);
		return -1;
	}

	memset (data, 0x12, dataLen);

	gettimeofday (&start, NULL);
	for (i = 0; i < cycle; i ++){
		if (0 != (ret = tcs_sm4_ecb_encrypt(key, data, dataLen, enc, &encLen))){
			printf ("tcs_sm4_ecb_mode_encrypt error: %d\n", ret);
			goto out;
		}
	}
	
	gettimeofday (&end, NULL);
	
	used_usec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	used_sec = used_usec / (float)1000000;
	printf ("  SM4 ecb mode encrypt speed  >>>  |size(KB): %-12.02f |times: %-8d |rate(Mbps): %f\n",
								(float)dataLen/1024, cycle, ((cycle*dataLen)/(float)(1024*1024))/used_sec*8);

#ifdef SM_CHECK
	sm4_importkey (&ctx, key, key);
	sm4_encrypt (&ctx, FM_ALGMODE_ECB, data, dataLen, soft_enc, &soft_encLen);

     // httc_util_dump_hex("sm4 self encrypt data : ",  soft_enc,  soft_encLen);
     // httc_util_dump_hex("sm4  encrypt data : ",  enc,  encLen);
		
	if (encLen != soft_encLen){
		printf ("encLen(%d) != soft_encLen(%d)\n", encLen, soft_encLen);
		//goto out;
	}
	if (memcmp (enc, soft_enc, encLen)){
		printf ("enc data is incorrent\n");
		//goto out;
	}	
#endif

	gettimeofday (&start, NULL);
	for (i = 0; i < cycle; i ++){
		if (0 != (ret = tcs_sm4_ecb_decrypt(key, enc, encLen, dec, &decLen))){
			printf ("tcs_sm4_ecb_mode_decrypt error: %d\n", ret);
			goto out;
		}
	}
	gettimeofday (&end, NULL);
	used_usec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	used_sec = used_usec / (float)1000000;
	printf ("  SM4 ecb mode decrypt speed  >>>  |size(KB): %-12.02f |times: %-8d |rate(Mbps): %f\n",
								(float)dataLen/1024, cycle, ((cycle*dataLen)/(float)(1024*1024))/used_sec*8);
	
	if (dataLen != decLen){
		printf ("dataLen(%d) != decLen(%d)\n", dataLen, decLen);
		goto out;
	}
	if (memcmp (data, dec, dataLen)){
		printf ("dec data diff origin data\n");
		goto out;
	}

out:
	httc_free (data);
	httc_free (enc);
	httc_free (soft_enc);
	httc_free (dec);

	return ret;	
}

