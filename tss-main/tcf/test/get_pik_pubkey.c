#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "httcutils/debug.h"
#include "tcfapi/tcf_attest.h"

int main(void)
{
	int ret = 0;
	uint8_t pubkey[64] = {0};
	uint32_t pubkey_len = sizeof(pubkey);
	
	ret = tcf_get_pik_pubkey(pubkey, &pubkey_len);
	if(ret) {
		printf("[tcf_get_pik_pubkey] ret: 0x%08x\n", ret);
		return -1;
	}
	else {
		printf("test tcf_get_pik_pubkey OK\n");
	}
	
	httc_util_dump_hex("pubKey", pubkey, pubkey_len);

	return 0;
}






