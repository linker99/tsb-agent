/**
****************************************************************************************
 * @FilePath: tcf_tpcm_selftest_test.c
 * @Author: wll
 * @Date: 2023-06-26 15:08:20
 * @LastEditors: 
 * @LastEditTime: 2023-06-26 15:19:40
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include "httcutils/debug.h"

#include "tcfapi/tcf_selftest.h"

void usage()
{
	printf ("\n"
			" Usage: ./tcf_tpcm_selftest_test \n"
			"    eg. ./tcf_tpcm_selftest_test\n"
			"\n");
}

static uint32_t set_error_flag(uint32_t *data,uint32_t bit){

    uint32_t temp = 0x1 << bit;
    *data = *data +temp;
    return 0;
}

static uint32_t get_error_flag(uint32_t data){

   if (&data == NULL) {
        printf("请输入数据\n");
        return -1;
   }
   uint32_t i=0;
   uint32_t flag=0;
   for(i;i<32;i++){
       flag = (data>>i)&0x1;
       if(flag==1){
            printf("ERROR :%d\n",i);
       }
   }
   return 0;
}

int main(int argc, char** argv){
	int ret = 0;
	uint32_t status = 0;
	ret = tcf_tpcm_selftest(&status);
	printf("ret %d\n",ret);
	if(ret!=0){
    	httc_util_dump_hex ("resut",&status,sizeof(uint32_t));
		get_error_flag(status);
	}
	return ret;
}

