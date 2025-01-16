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

#define DEFAULT_HASH_SIZE 32 
static void usage()
{
    printf("\n"
           " Usage: ./sm3_verify -s <hex-size> # for pantum\n"
           "        -s <hex-size>      - the hex-size(Bytes) of data to SM3\n"
           "    eg. ./sm3_verify -s 0x1000\n");
}

int main(int argc, char **argv)
{
    int ret = 0;
    int ch = 0;
    int i = 0;
    int cycle = 1;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    uint8_t output[DEFAULT_HASH_SIZE] = {0};
    uint32_t olen = 0;
    uint8_t verify[DEFAULT_HASH_SIZE] = {0};

    while ((ch = getopt(argc, argv, "s:h")) != -1)
    {
        switch (ch)
        {
        case 's':
            dataLen = strtol(optarg, NULL, 16);
            break;
        case 'h':
            usage();
            return 0;
        }
    }

    if (!dataLen)
    {
        usage();
        return -1;
    }

    if (NULL == (data = httc_malloc(dataLen)))
    {
        printf("Malloc for data error, size = %d\n", dataLen);
        return -1;
    }
    memset(data, 0x12, dataLen);
    sm3(data, dataLen, verify);
    if (0 != (ret = tcs_sm3_verify(data, dataLen, verify, DEFAULT_HASH_SIZE)))
    {
        printf("tpcm_sm3_verify error: %d\n", ret);
        httc_free(data);
        return -1;
    }

    if (data)
        httc_free(data);
    return ret;
}

