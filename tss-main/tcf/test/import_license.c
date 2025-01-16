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
#include "tcsapi/tcs_error.h"


uint32_t license_type = LICENSE_ATTR_TPCM;
uint32_t license_stype = LICENSE_LTYPE_ZERO;
uint32_t env_type = 0; // 1: simulator env.

uint8_t  platform_privkey[32] = {
			0x05, 0x28, 0x13, 0x09, 0xDE, 0x68, 0xDC, 0x09, 0x85, 0x6C, 0x13, 0x9E, 0x03, 0x33, 0x54, 0x3A,
			0xA2, 0x31, 0x54, 0x55, 0xC3, 0x31, 0xFB, 0x26, 0x7E, 0xC3, 0x63, 0xD0, 0x0B, 0xA4, 0x67, 0xF7};
uint32_t platform_privkey_len = sizeof (platform_privkey);
uint8_t  platform_pubkey[64] = {
			0x1B, 0x25, 0x77, 0x5A, 0x05, 0x15, 0x1F, 0xF7, 0x17, 0xD1, 0x62, 0xD1, 0xEE, 0x31, 0xD6, 0x8F,
			0x7A, 0x67, 0x02, 0xC8, 0x8E, 0x32, 0xB7, 0x42, 0x0D, 0xEB, 0xF3, 0x8B, 0xB3, 0x4F, 0x00, 0xB4,
			0xF7, 0xF7, 0xEC, 0x8D, 0x42, 0x84, 0x82, 0x20, 0x50, 0x84, 0x7A, 0x44, 0x01, 0x32, 0x91, 0x98,
			0x5B, 0x7D, 0x7C, 0xF7, 0x06, 0x9D, 0x7B, 0x48, 0xBE, 0x0E, 0xCE, 0x6F, 0x19, 0x6B, 0x4D, 0xD9};
uint32_t platform_pubkey_len = sizeof (platform_pubkey);

uint8_t simulator_privkey[32] = {
0x72, 0x82, 0xff, 0x38, 0x43, 0xd9, 0xec, 0xad, 0xf5, 0xc1, 0xf3, 0x2b, 0xc5, 0x71, 0xbf, 0x71,
0x1d, 0xa8, 0x7a, 0x6a, 0x29, 0x25, 0x7c, 0xfd, 0x7e, 0x95, 0x04, 0x02, 0xcc, 0x06, 0xac, 0xf1};
uint32_t simulator_privkey_len = sizeof (simulator_privkey);
uint8_t simulator_pubkey[64] = {
0xc0, 0x4b, 0xaf, 0x8e, 0x4f, 0x91, 0x3d, 0x0f, 0xcf, 0x06, 0xf4, 0x71, 0x8f, 0x30, 0x86, 0x5a,
0xce, 0xeb, 0xef, 0xf6, 0xd6, 0x88, 0x2e, 0x32, 0x4d, 0xa2, 0xb7, 0xb5, 0xca, 0xa8, 0xf0, 0x64,
0x93, 0xe1, 0x63, 0x48, 0xdd, 0x9e, 0xb4, 0xbb, 0x9f, 0xf3, 0xb1, 0xf8, 0x7f, 0x07, 0xcf, 0xec,
0xfe, 0xc6, 0x4a, 0x80, 0x85, 0xe0, 0xee, 0x20, 0x81, 0x51, 0xc6, 0x71, 0x54, 0x3f, 0x05, 0x8b};
uint32_t simulator_pubkey_len = sizeof (simulator_pubkey);

int license_request(struct license_req *license_req)
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
	
	printf("license_type : %d, version : %d\n", license_type, license_stype);
	printf("input license_type : %d, 0x%08x\n", iParam.license_type, iParam.license_type);
	ret = tcf_generate_license_request(license_req, &iParam);
	if(ret) {
		printf ("[%s:%d]ret: %d\n", __func__, __LINE__, ret);
		return -1;
	}

	printf("license_type : %d\n", ntohl(license_req->be_license_type));
	printf("client_id_length : %d\n", ntohl(license_req->be_client_id_length));

	printf("tpcm_id_length : %d\n", ntohl(license_req->be_tpcm_id_length));
	printf("host_id_length : %d\n", ntohl(license_req->be_host_id_length));
	printf("ekpub_length : %d\n", ntohl(license_req->be_ekpub_length));
	printf("signature_size : %d\n", ntohl(license_req->be_signature_size));
	httc_util_time_print ("time_stamp : %s\n", ntohll(license_req->be_time_stamp));
	httc_util_dump_hex ("client_id", license_req->client_id, ntohl(license_req->be_client_id_length));
	httc_util_dump_hex ("tpcm_id", license_req->tpcm_id, ntohl(license_req->be_host_id_length));
	httc_util_dump_hex ("host_id", license_req->host_id, ntohl(license_req->be_host_id_length));
	httc_util_dump_hex ("ekpub", license_req->ekpub, ntohl(license_req->be_ekpub_length));
	httc_util_dump_hex ("signature", license_req->signature, ntohl(license_req->be_signature_size));

	if (!env_type)
	{
		ret = tcs_get_pik_pubkey(pubkey, &pubkey_len);
		if(ret) {
			printf("[tcs_get_pik_pubkey] ret: 0x%08x\n", ret);
			return -1;
		}

		ret = os_sm2_verify((uint8_t*)license_req,
				sizeof(struct license_req), pubkey, ntohl(pubkey_len), license_req->signature, ntohl(license_req->be_signature_size));
	}
	else
	{
		ret = os_sm2_verify((uint8_t*)license_req,
				sizeof(struct license_req), simulator_pubkey, ntohl(simulator_pubkey_len), license_req->signature, ntohl(license_req->be_signature_size));
	}
	printf("License Request Verify %s(%d)!\n", (ret == 0) ? "success" : "failure", ret);
	
	return ret;
}

int test_import_license(struct license_req *license_req)
{
	int ret = 0;
	uint8_t *sig = NULL;
	uint32_t siglen = 0;
	struct timeval tv;
	struct license *license = NULL;
	
	if((ret = gettimeofday(&tv, NULL)) != 0) {
		perror("gettimeofday error");
		return ret;
	}

	license = (struct license *)httc_malloc(sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
	if(license == NULL) {
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		httc_free (license_req);
		return TSS_ERR_NOMEM;
	}

	license->be_license_type = license_req->be_license_type;
	license->be_client_id_length = license_req->be_client_id_length;
	license->be_tpcm_id_length = license_req->be_tpcm_id_length;
	license->be_host_id_length = license_req->be_host_id_length;
	license->be_ekpub_length = license_req->be_ekpub_length;
	license->be_signature_size = license_req->be_signature_size;
	license->be_time_stamp = license_req->be_time_stamp;
	license->be_deadline = htonll (tv.tv_sec + ntohl (license_req->be_shelf_life )* 24 * 3600);
	memcpy (license->client_id, license_req->client_id, ntohl (license_req->be_client_id_length));
	memcpy (license->tpcm_id, license_req->tpcm_id, ntohl (license_req->be_tpcm_id_length));
	memcpy (license->host_id, license_req->host_id, ntohl (license_req->be_host_id_length));
	memcpy (license->ekpub, license_req->client_id, ntohl (license_req->be_ekpub_length));	

	if((ret = os_sm2_sign((uint8_t*)license, sizeof(struct license),
				platform_privkey, platform_privkey_len, platform_pubkey, platform_pubkey_len, &sig, &siglen)) != 0) {
		printf("os_sm2_sign for license error (%d)\n", ret);
		return ret;
	}
	memcpy(license->signature, sig, siglen);


	httc_util_time_print ("time_stamp : %s\n", ntohll(license->be_time_stamp));
	httc_util_time_print ("deadline : %s\n", ntohll(license->be_deadline));

	ret = tcf_import_license(license);
	if(ret) {
		printf("[TPCM_ImportLicense Time: 0x%08x]ret: 0x%08x\n", (uint32_t)tv.tv_sec, ret);
		ret = -1;
	}

	SM2_FREE(sig);

	return ret;	
}

static void usage (void)
{
	printf ("\n"
			"  Usage: ./import_license -t <type> -s <version type> -e <env type>\n"
			"  options:\n"
			"        -t <type>    : license type,v2.0(1:test　2:TPCM　3:TPCM && TSB),v2.1(1:TPCM)\n"
			"        -s <vtype>   : license version type (0-v2.0; 1-v2.1)\n"
			"        -e <env type> : environment type (1-simulator ; 2-other)\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	struct license_req *license_req = NULL;
	
	if (argc >= 3){
		license_type = atoi (argv[2]);
		if (argc >= 5)
		{
			license_stype = atoi (argv[4]);
			if (argc >= 7)
			{
				env_type = atoi (argv[6]);
			}
		}
	}
	
	license_req = (struct license_req *)httc_malloc(sizeof(struct license_req) + DEFAULT_SIGNATURE_SIZE);
	if(license_req == NULL) {
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return -ENOMEM;
	}

	if((ret = license_request(license_req)) != 0) {
		printf("test_license_request, ret = %d\n", ret);
		httc_free (license_req);
		return -1;
	}
	if((ret = test_import_license(license_req)) != 0) {
		printf("test_import_license, ret = %d\n", ret);
		ret = -1;
	}

	if (license_req) httc_free(license_req);
	
	return ret;
}


