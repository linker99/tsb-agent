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

static int util_tcm_nv_writevalue (uint32_t index, uint8_t *nvpwd, uint8_t *data, uint32_t datalen)
{
	uint32_t ret = 0;
	uint32_t offset = 0;
	char nvauth[DEFAULT_HASH_SIZE] = {0};
	char ownauth[DEFAULT_HASH_SIZE] = {0};
	TCM_PCR_INFO_SHORT pcrInfoRead;
	TCM_PCR_INFO_SHORT pcrInfoWrite;
	uint32_t permissions = TCM_NV_PER_AUTHREAD | TCM_NV_PER_AUTHWRITE;

	TCM_setlog(0);
	
	memset(&pcrInfoRead, 0x0, sizeof(pcrInfoRead));
	pcrInfoRead.localityAtRelease = TCM_LOC_ZERO;

	memset(&pcrInfoWrite, 0x0, sizeof(pcrInfoWrite));
	pcrInfoWrite.localityAtRelease = TCM_LOC_ZERO;

	sm3 (ownpwd, strlen (ownpwd), ownauth);
	sm3 (nvpwd, strlen (nvpwd), nvauth);

	/** Definespace **/
	ret = TCM_NV_DefineSpace2(ownauth, index, datalen,
					permissions, nvauth, &pcrInfoRead, &pcrInfoWrite);
	if (0 != ret) {
		printf("Error '%s' from TCM_NV_DefineSpace2().\n", TCM_GetErrMsg(ret));
		return ret;
	}

	/** Write Data **/
	ret = TCM_NV_WriteValueAuth(index, offset, data, datalen, nvauth);
	if(ret != 0){
		printf("Error %s from NV_WriteValueAuth\n", TCM_GetErrMsg(ret));
	}

	return ret;
}

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
			" Usage: ./cert_write -p <pwd> -c <cert>\n"
			"        -p <pwd>      - cert read password\n"
			"        -c <cert>     - cert being to write\n"
			"    eg. ./cert_read -p abc\n");
}

int main (int argc, char** argv)
{
	int ch = 0;
	int ret = 0;
	uint32_t index = 0x1000;
	char* nvpwd = NULL;
	char* cert = NULL;
	int certlen = 0;

	while ((ch = getopt(argc, argv, "p:c:h")) != -1)
	{
		switch (ch)
		{
			case 'p':
				nvpwd = optarg;
				break;
			case 'c':
				cert = optarg;
				certlen = strlen (cert);
				break;
			case 'h':
				usage ();
				return 0;	
		}
	}

	if (!cert || !nvpwd)	usage ();
	
	if (0 != (ret = util_tcm_nv_writevalue (index, nvpwd, cert, certlen))){
		//printf ("nv_writevalue error: %d\n", ret);
		return -1;
	}

	printf ("Cert write success!\n");
}


