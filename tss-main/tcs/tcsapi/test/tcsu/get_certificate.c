/*************************************************************************
	> File Name: test.c
	> Author: 
	> Mail: 
	> Created Time: 2021年05月14日 星期五 14时41分15秒
 ************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "mem.h"
#include "debug.h"
#include "tcs_attest.h"

int main(void)
{
	int r;
    int i = 0;
    int number = 0;
    struct remote_cert *cert = NULL;
    if ((r = tcs_get_remote_certs(&cert, &number))){
    	httc_util_pr_error ("tcs_get_remote_certs error :%d(0x%x)\n", r, r);
		return -1;
	}

    printf("remote cert:\n");
    for(i = 0;i < number; i++){
        printf("  [%d].alg: %d\n", i, ntohl (cert[i].be_alg));
        printf("  [%d].length: %d\n", i, ntohl (cert[i].be_length));
        printf("  [%d].", i); httc_util_dump_hex ("id", cert[i].id, MAX_TPCM_ID_SIZE);
        printf("  [%d].", i); httc_util_dump_hex ("cert", cert[i].cert, ntohl (cert[i].be_length));
    }
	
	if (cert)	httc_free (cert);
    return 0;
}
