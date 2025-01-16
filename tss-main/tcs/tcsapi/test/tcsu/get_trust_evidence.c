#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "sys.h"
#include "debug.h"
#include "convert.h"
#include "tutils.h"
#include "tcs_attest.h"
#include "tcs_constant.h"
#include "tcs_attest_def.h"

int main(void){
	int ret = 0;
	unsigned char *host_id = "01234567890123456789012345678901";
	struct trust_evidence evi;
	uint64_t nonce = 0x12345678;
	
	unsigned char attached_hash[DEFAULT_HASH_SIZE] = {0};
	memset (attached_hash, 0x12, DEFAULT_HASH_SIZE);
	
	ret = tcs_generate_trust_evidence(&evi,nonce,host_id,attached_hash);
	if(!ret && (nonce == ntohll(evi.be_nonce))){
		printf ("evidence.be_nonce: 0x%016lX\n", ntohll(evi.be_nonce));
		printf ("evidence.be_eval: 0x%08X\n", ntohl (evi.be_eval));
		printf ("evidence.be_boot_times: 0x%08X\n", ntohl (evi.be_boot_times));
	    printf ("evidence.be_tpcm_time: 0x%08X\n", ntohl (evi.be_tpcm_time));
		httc_util_time_print ("evidence.be_tpcm_report_time: %s\n", ntohll (evi.be_tpcm_report_time));
		httc_util_dump_hex ("evidence.tpcm_id", evi.tpcm_id, MAX_TPCM_ID_SIZE);
		httc_util_dump_hex ("evidence.host_id", evi.host_id, MAX_HOST_ID_SIZE);
		httc_util_dump_hex ("evidence.attached_hash", evi.attached_hash, MAX_HOST_ID_SIZE);
		httc_util_dump_hex ("evidence.signature", evi.signature, DEFAULT_SIGNATURE_SIZE);
		return 0;
	}
	printf("tcs_generate_trust_evidence ret:0x%08X\n",ret);
	return -1;
}

