#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <inttypes.h>  

#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_attest_def.h"
#include "tcs_policy_def.h"
#include "tutils.h"



  
static void print_ip_from_uint32(uint32_t ip_num) {  
	uint8_t octets[4];  
    // 将32位整数分为4个字节  
    octets[0] = (ip_num >> 24) & 0xFF;  
    octets[1] = (ip_num >> 16) & 0xFF;  
    octets[2] = (ip_num >> 8) & 0xFF;  
    octets[3] = ip_num & 0xFF;    
    // 打印IP地址  
    printf("%u.%u.%u.%u\n", octets[3], octets[2], octets[1], octets[0]);  
} 


int main(void){
	int ret = 0;
	int i =0;
	uint32_t hostip[10];
	uint32_t num=10;
	ret = tcs_get_ruida_ip(hostip, &num);
	printf("num : %d\n",num);
	for(i=0;i<num;i++){
		print_ip_from_uint32(hostip[i]);
	}
	return ret;
}


