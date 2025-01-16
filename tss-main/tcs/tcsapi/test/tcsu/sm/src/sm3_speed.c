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
#include "mem.h"

#define SM_CHECK

static void usage ()
{
	printf ("\n"
			" Usage: ./sm3_speed -s <hex-size> [ -t <times> ]\n"
			"        -s <hex-size>      - the hex-size(Bytes) of data to SM3\n"
			"        -t <times>         - the times of test sm3 <default: 1>"
			"    eg. ./sm3_speed -s 0x1000\n"
			"        ./sm3_speed -s 0x1000 -t 100\n");
}

static void dump_hex_print(const uint8_t *str, int len)
{
    int i = 1;
    
    printf(" [0] : ");
    for(i; i <= len; i++)
        { 
          printf("0x%x ", str[i]);
          if(i%10 == 0)
            {
              printf("\n");
              printf(" [%d] : ", i);
            }
        }
    printf("\n");              
}

int main (int argc, char **argv)
{
	int ret = 0;
	int ch = 0;
	int i = 0;
	int cycle = 1;
	uint8_t *data = NULL;
	uint32_t dataLen = 0;
	uint8_t output[DEFAULT_HASH_SIZE] = {0};
        uint32_t olen = 0;
	uint8_t soft_output[DEFAULT_HASH_SIZE] = {0};
	struct timeval start;
	struct timeval end;
	uint64_t used_usec = 0;
	float used_sec = 0;
	
	while ((ch = getopt(argc, argv, "s:t:h")) != -1)
	{
		switch (ch)
		{
			case 's':
				dataLen = strtol (optarg, NULL, 16);
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
	memset (data, 0x12, dataLen);

	gettimeofday (&start, NULL);
	for (i = 0; i < cycle; i ++){
		if (0 != (ret = tcs_sm3 (data, dataLen, output, &olen))){
			printf ("tpcm_sm3 error: %d\n", ret);
			httc_free (data);
			return -1;
		}
	}
      // printf(" olen = %d \n", olen);
	gettimeofday (&end, NULL);
	
	used_usec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	used_sec = used_usec / (float)1000000 ;
	printf ("  SM3 speed  >>>  |size(KB): %-12.02f |times: %-8d |rate(Mbps): %f\n",
								(float)dataLen/1024, cycle, ((cycle*dataLen)/(float)(1024*1024))/used_sec*8);

#ifdef SM_CHECK
	sm3 (data, dataLen, soft_output);
	if (memcmp (output, soft_output, DEFAULT_HASH_SIZE)){
                httc_util_dump_hex("hard hash", output, DEFAULT_HASH_SIZE);
                httc_util_dump_hex("soft hash", soft_output, DEFAULT_HASH_SIZE);
		printf ("dec data diff origin data\n");
		if (data) httc_free (data);
		return -1;
	}
#endif
       // httc_util_dump_hex("hard hash", output, DEFAULT_HASH_SIZE);
       // httc_util_dump_hex("soft hash", soft_output, DEFAULT_HASH_SIZE);
        
	if (data) httc_free (data);
	return ret;	
}


