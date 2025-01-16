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


#define DEFAULT_HASH_SIZE 32 

static void usage()
{
    printf("\n"
           " Usage: ./sm3_verify # for pantum");
}

int main(int argc, char **argv)
{
    int ret = 0;
    int ch = 0;
    uint8_t data [] = {
            0xFE, 0x27, 0x6C, 0x2C, 0xAC, 0x0E, 0x97, 0xB9,
            0x34, 0xD9, 0x70, 0xC9, 0x9E, 0xAA, 0xBE, 0xEA, 
            0xC1, 0x27, 0xA8, 0x1D, 0x83, 0x2B, 0xD4, 0xA7,
            0x34, 0xC9, 0x06, 0x9C, 0x97, 0xB6, 0x6A, 0xE4, 
            0x00, 0x54, 0x1A, 0xA2, 0x18, 0xD3, 0x9D, 0x2A, 
            0xA5, 0x06, 0x13, 0x4B, 0xBA, 0x2A, 0x69, 0x70,
            0x26, 0xA1, 0x31, 0x27, 0x18, 0x95, 0xE0, 0x91, 
            0x2D, 0xE4, 0x5E, 0x2A, 0x7B,
    };
    uint32_t dataLen = sizeof(data);

    uint8_t verify[DEFAULT_HASH_SIZE] = {
        	0x47, 0xE3, 0x76, 0xAB, 0xC0, 0xFA, 0x6B, 0xAB, 
            0x2C, 0x4B, 0x63, 0x74, 0x3B, 0x1C, 0x0E, 0xA0, 
            0xDC, 0x4F, 0x74, 0xBD, 0xA8, 0xF3, 0x53, 0xDF,
            0x8B, 0x8C, 0x1D, 0x84, 0x1F, 0xFF, 0x58, 0x04
    };

    while ((ch = getopt(argc, argv, "h")) != -1)
    {
        switch (ch)
        {
        case 'h':
            usage();
            return 0;
        }
    }

    printf("case 1 测试正确值，期望返回 0\n");
    ret = tcs_sm3_verify(data, dataLen, verify, DEFAULT_HASH_SIZE);
    if(ret)
    {
        printf("tpcm_sm3_verify case 1 failed: %d\n", ret);
        return -1;
    }
    printf("tpcm_sm3_verify case 1 success\n");

    printf("case 2 测试错误值，期望返回非零\n");
    verify[0]= 0xff;
    ret = tcs_sm3_verify(data, dataLen, verify, DEFAULT_HASH_SIZE);
    if(!ret)
    {
        printf("tpcm_sm3_verify case 2 failed: %d\n", ret);
        return -1;
    }
    printf("tpcm_sm3_verify case 2 success retval %d\n",ret);

    return 0;

}


