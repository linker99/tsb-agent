#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcm.h"
#include "tcmfunc.h"
#include "tcm_error.h"
//#include "tpcm_utils.h"
//#include "tpcm_sm.h"
#include "tcs_constant.h"

char *ownpwd = "123";

static int util_tcm_nv_readvalue (uint32_t index, uint8_t *nvpwd, uint8_t *data, uint32_t *datalen)
{
	uint32_t ret = 0;
	uint32_t offset = 0;
	char nvauth[DEFAULT_HASH_SIZE] = {0};
	uint32_t cap = TCM_CAP_NV_INDEX;
	STACK_TCM_BUFFER(resp);
	STACK_TCM_BUFFER( subcap );
	TCM_NV_DATA_PUBLIC ndp;
    STACK_TCM_BUFFER(tb);
	
	TCM_setlog(0);

	STORE32(subcap.buffer, 0, index);
    subcap.used = 4;			

	sm3 (nvpwd, strlen (nvpwd), nvauth);
	
	/** Get Datalength **/
    ret = TCM_GetCapability(cap, &subcap, &resp);
    if (0 != ret) {
	    printf("TCM_GetCapability returned %s.\n",
	           TCM_GetErrMsg(ret));
	    return ret;
	}
	
    TSS_SetTCMBuffer(&tb, resp.buffer, resp.used);
    ret = TCM_ReadNVDataPublic(&tb, 0, &ndp);
    if ( ( ret & ERR_MASK) != 0) {
        printf("Could not deserialize the TCM_NV_DATA_PUBLIC structure.\n");
        return ret;
    }
	
	*datalen = (*datalen < (unsigned int)ndp.dataSize)? *datalen : (unsigned int)ndp.dataSize;
	
	/** Read Data **/
	ret = TCM_NV_ReadValueAuth(index, offset, *datalen, data, datalen, nvauth);
	if(ret != 0){
		printf("Error %s from TCM_NV_ReadValueAuth\n",
	    TCM_GetErrMsg(ret));
	}
	
	return ret;
}

static void usage ()
{
	printf ("\n"
			" Usage: ./cert_read -p <pwd>\n"
			"        -p <pwd>      - cert read password\n"
			"    eg. ./cert_read -p abc\n");
}

int main (int argc, char** argv)
{
	int ch = 0;
	int ret = 0;
	uint32_t index = 0x1000;
	char* nvpwd = NULL;

	char cert[1024] = {0};
	int certlen = sizeof (cert);

	while ((ch = getopt(argc, argv, "p:h")) != -1)
	{
		switch (ch)
		{
			case 'p':
				nvpwd = optarg;
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}

	if (!nvpwd)	usage ();
	
	if (0 != (ret = util_tcm_nv_readvalue (index, nvpwd, cert, &certlen))){
		return -1;
	}

	printf ("Cert read success: %s\n", cert);
	return 0;
}


