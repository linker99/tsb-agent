#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "tcs_attest.h"
#include "tcs_maintain.h"
#include "tcmfunc.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./generage_tpcm_pik <pwd>\n"
			"        -pwd           - The password string\n"
			"        eg. ./generate_tpcm_pik httc@123\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	uint8_t *own = NULL;

	if (argc != 2){
		usage ();
		return -1;
	}

	TCM_setlog(0);
	own = argv[1];
	
	ret = tcs_generate_tpcm_pik(own);
	if(ret) {
		printf("TCM_CreatePIK error: 0x%08x\n", ret);
		return -1;
	}
	
	return 0;
}


