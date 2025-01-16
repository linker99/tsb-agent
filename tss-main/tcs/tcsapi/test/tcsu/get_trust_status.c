#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tcs_attest.h"

extern int tcs_get_dmeasure_trust_status(uint32_t *status);
extern int tcs_get_intercept_trust_status(uint32_t *status);

int main(void)
{
	int ret = 0;
	uint32_t status;
	uint32_t dmstatus;
	uint32_t imstatus;
	
	if((ret = tcs_get_trust_status(&status)) == 0) {
		tcs_get_dmeasure_trust_status(&dmstatus);
		tcs_get_intercept_trust_status (&imstatus);
		printf("[tcs_get_trust_status] Trusted status: %d, dm status: %d, im status: %d\n",
						status, dmstatus, imstatus);		
	}
	else {
		printf("[tcs_get_trust_status] ret: 0x%08x\n", ret);
		return -1;
	}

	return 0;
}





