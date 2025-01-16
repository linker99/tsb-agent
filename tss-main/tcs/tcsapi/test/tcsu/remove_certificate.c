/*************************************************************************
	> File Name: test.c
	> Author: 
	> Mail: 
	> Created Time: 2021年05月14日 星期五 14时41分15秒
 ************************************************************************/
#include <stdio.h>

#include "debug.h"
#include "tcs_attest.h"

void usage()
{
    printf("\n");
    printf("  Usage: ./remove_certificate <id> \n");
    printf("         id   	- cert id (32 Bytes)\n");
    printf("     eg  ./creat_certificate test1");
    printf("\n");
}

int main (int argc, char **argv)
{
	int r;
	if (argc != 2){
		usage ();
		return -1;
	}
    if ((r = tcs_remove_remote_cert (argv[1]))){
		httc_util_pr_error ("tcs_remove_remote_cert error :%d(0x%x)\n", r, r);
		return -1;
	}
    return 0;
}
