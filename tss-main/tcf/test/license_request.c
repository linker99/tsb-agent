#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#include "httcutils/sys.h"
#include "httcutils/mem.h"
#include <httcutils/debug.h>
#include "tcsapi/tcs_license_def.h"
#include "tcfapi/tcf_license.h"
#include "httcutils/convert.h"
#include "crypto/sm/sm2_if.h"
#include "tcsapi/tcs_attest.h"

uint32_t license_type = LICENSE_ATTR_TPCM;
uint32_t license_stype = LICENSE_LTYPE_ZERO;

int test_license_request(struct license_req *license_req)
{
	int ret = 0;
	struct license_param iParam;
	uint8_t pubkey[64] = {0};
	uint32_t pubkey_len = sizeof(pubkey);

	iParam.license_type = (license_stype << 16);
	iParam.license_type |= license_type;
	iParam.shelf_life = 30;
	iParam.client_id_length = 32;
	iParam.host_id_length = 32;
	memset(iParam.client_id, 0xAC, MAX_CLIENT_ID_SIZE);
	memset(iParam.host_id, 0xAB, MAX_HOST_ID_SIZE);
	
	ret = tcf_generate_license_request(license_req, &iParam);
	if(ret) {
		printf ("[%s:%d]ret: %d\n", __func__, __LINE__, ret);
		return -1;
	}

	//httc_util_dump_hex ("license_req", license_req, sizeof (struct license_req));
	printf("license_type : %d\n", ntohl(license_req->be_license_type));
	printf("shelf_life : %d\n", ntohl(license_req->be_shelf_life));
	printf("client_id_length : %d\n", ntohl(license_req->be_client_id_length));
	printf("tpcm_id_length : %d\n", ntohl(license_req->be_tpcm_id_length));
	printf("host_id_length : %d\n", ntohl(license_req->be_host_id_length));
	printf("ekpub_length : %d\n", ntohl(license_req->be_ekpub_length));
	printf("signature_size : %d\n", ntohl(license_req->be_signature_size));
	httc_util_time_print ("time_stamp : %s\n", ntohll(license_req->be_time_stamp));
	httc_util_dump_hex("client_id", license_req->client_id, ntohl(license_req->be_client_id_length));
	httc_util_dump_hex("tpcm_id", license_req->tpcm_id, ntohl(license_req->be_host_id_length));
	httc_util_dump_hex("host_id", license_req->host_id, ntohl(license_req->be_host_id_length));
	httc_util_dump_hex("ekpub", license_req->ekpub, ntohl(license_req->be_ekpub_length));
	httc_util_dump_hex ("signature", license_req->signature, ntohl(license_req->be_signature_size));

	ret = tcs_get_pik_pubkey(pubkey, &pubkey_len);
	if(ret) {
		printf("[tcs_get_tpcm_pik_pubkey] ret: 0x%08x\n", ret);
		return -1;
	}
	//httc_util_dump_hex("pubKey", pubkey, pubkey_len);
	ret = os_sm2_verify((uint8_t*)license_req,
			sizeof(struct license_req), pubkey, pubkey_len, license_req->signature, ntohl(license_req->be_signature_size));
	printf("License Request Verify %s(%d)!\n", (ret == 0) ? "success" : "failure", ret);
	
	return ret;
}


int main (int argc, char **argv)
{
	int ret = 0;
	struct license_req *license_req = NULL;
	
	if (NULL == (license_req = (struct license_req *)httc_malloc(sizeof(struct license_req) + DEFAULT_SIGNATURE_SIZE))){
		printf ("Malloc for license req error\n");
		return -ENOMEM;
	}
	if((ret = test_license_request(license_req)) == 0) {
		printf("test_license_request OK\n");
	}
	else {
		printf("test_license_request fail, ret = %d\n", ret);
		ret = -1;
	}

	if(license_req != NULL)	httc_free(license_req);
	
	return ret;
}