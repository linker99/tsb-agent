#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

#include "tcfapi/tcf_log_notice.h"
#include "tcsapi/tcs_notice.h"

int main(void){

	int ret = 0;
	uint64_t version = 0;
	
	ret = tcf_write_notices((unsigned char *)&version, sizeof(uint64_t), NOTICE_POLICIES_VERSION_UPDATED);
	if(ret){
		printf("[Error] tcf_write_notices ret:0x%08X\n",ret);
		return -1;
	}
	
	return ret;
}



