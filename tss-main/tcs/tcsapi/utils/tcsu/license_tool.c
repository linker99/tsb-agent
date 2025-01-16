#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "sys.h"
#include "file.h"
#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_license.h"
#include "tcs_attest.h"
#include "../tcm/lib/crypto/sm/sm2_if.h"

const char * license_desc[LICENSE_ATTR_MAX] = {"ALL", "TPCM", "TSB", "TERM", "RESERVED"};
const char * license_type_desc[LICENSE_LTYPE_MAX] = {"V2.0", "V2.1"};
uint32_t license_type = LICENSE_ATTR_TPCM;
uint32_t license_stype = LICENSE_LTYPE_ONE;
uint32_t g_file_type = 0;		//write req date to file or not.
uint32_t g_license_export = 0;	//write license date to file or not.
uint8_t *license_path_out = NULL;
uint8_t *license_path_export = NULL;

#define TPCM_PRIVKEY_STR_LEN	64
#define TPCM_PUBKEY_STR_LEN		128


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
uint64_t limit = 24 * 3600;
struct license *license = NULL;
struct license_req *g_license_req = NULL;

static void binary_to_str(void *src, char *dst, int dst_len)
{
	unsigned int i;

	for (i=0; i<dst_len/2; i++) {
		sprintf(dst + i*2, "%02X", ((unsigned char *)src)[i]);
	}
}

int license_request(struct license_req *license_req)
{
	int ret = 0;
	struct license_param iParam;
	uint8_t pubkey[64] = {0};
	uint32_t pubkey_len = sizeof(pubkey);
	char req_str[(sizeof(struct license_req) + DEFAULT_SIGNATURE_SIZE) * 2 + 1] = {0};
	uint8_t id[128] = {0};
	uint8_t path[512] = {0};
	uint32_t id_len = sizeof(id);


	if (!license_req->be_license_type)
	{
		iParam.license_type = (license_stype << 16);
		iParam.license_type |= license_type;
	}
	else
	{
		iParam.license_type = license_req->be_license_type;
	}
	iParam.shelf_life = limit;
	iParam.client_id_length = license_req->be_client_id_length;
	iParam.host_id_length = license_req->be_host_id_length;
	memcpy(iParam.client_id, license_req->client_id, MAX_CLIENT_ID_SIZE);
	memcpy(iParam.host_id, license_req->host_id, MAX_HOST_ID_SIZE);

	ret = tcs_generate_license_request(license_req, &iParam);
	if(ret) {
		printf ("[%s:%d]ret: %d\n", __func__, __LINE__, ret);
		return -1;
	}

	printf("license_type    : %d\n", ntohl(license_req->be_license_type));
	printf("client_id_length: %d\n", ntohl(license_req->be_client_id_length));
	printf("tpcm_id_length  : %d\n", ntohl(license_req->be_tpcm_id_length));
	printf("host_id_length  : %d\n", ntohl(license_req->be_host_id_length));
	printf("ekpub_length    : %d\n", ntohl(license_req->be_ekpub_length));
	printf("signature_size  : %d\n", ntohl(license_req->be_signature_size));
	httc_util_time_print ("time_stamp      : %s\n", ntohll(license_req->be_time_stamp));
	httc_util_dump_hex ("client_id", license_req->client_id, ntohl(license_req->be_client_id_length));
	httc_util_dump_hex ("tpcm_id", license_req->tpcm_id, ntohl(license_req->be_tpcm_id_length));
	httc_util_dump_hex ("host_id", license_req->host_id, ntohl(license_req->be_host_id_length));
	httc_util_dump_hex ("ekpub", license_req->ekpub, ntohl(license_req->be_ekpub_length));
	httc_util_dump_hex ("signature", license_req->signature, ntohl(license_req->be_signature_size));

	ret = tcs_get_pik_pubkey(pubkey, &pubkey_len);
	if(ret) {
		printf("[tcs_get_pik_pubkey] ret: 0x%08x\n", ret);
		return -1;
	}

	ret = os_sm2_verify((uint8_t*)license_req,
			sizeof(struct license_req), pubkey, ntohl(pubkey_len), license_req->signature, ntohl(license_req->be_signature_size));
	printf("License Request Verify %s(%d)!\n", (ret == 0) ? "success" : "failure", ret);

	if (g_file_type)
	{
		binary_to_str((void *)license_req, req_str, sizeof(req_str));
		httc_util_dump_hex ("license_req", license_req, sizeof(struct license_req));
		if (license_path_out)
		{
			ret = tcs_get_tpcm_id(id, &id_len);
			if(ret) {
				printf("[tcs_get_tpcm_id] ret: 0x%08x\n", ret);
				return -1;
			}
			sprintf(path, "%s%s-1.license", license_path_out,id);
			ret = httc_util_file_write(path, (const char *)license_req, sizeof(struct license_req));
			if (ret != sizeof(struct license_req)){
				httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)sizeof(struct license_req));
				return -1;
			}
			else
			{
				ret = 0;
			}
		}
		else
		{
			httc_util_pr_error ("httc_util_file_write error: file does not exist !\n");
			return -1;
		}
	}

	return ret;
}

int import_license(struct license_req *license_req)
{
	int ret = 0;
	uint8_t *sig = NULL;
	uint32_t siglen = 0;
	struct timeval tv;

	if(license == NULL){

		if( 0 != (ret = license_request(license_req))) return ret;

		license = (struct license *)httc_malloc(sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
		if(license == NULL) {
			printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
			return TSS_ERR_NOMEM;
		}

		if((ret = gettimeofday(&tv, NULL)) != 0) {
			perror("gettimeofday error");
			goto out;
		}

		license->be_license_type = license_req->be_license_type;
		license->be_client_id_length = license_req->be_client_id_length;
		license->be_tpcm_id_length = license_req->be_tpcm_id_length;
		license->be_host_id_length = license_req->be_host_id_length;
		license->be_ekpub_length = license_req->be_ekpub_length;
		license->be_signature_size = license_req->be_signature_size;
		license->be_time_stamp = license_req->be_time_stamp;
		license->be_deadline = htonll (tv.tv_sec + limit);
		memcpy (license->client_id, license_req->client_id, ntohl (license_req->be_client_id_length));
		memcpy (license->tpcm_id, license_req->tpcm_id, ntohl (license_req->be_tpcm_id_length));
		memcpy (license->host_id, license_req->host_id, ntohl (license_req->be_host_id_length));
		memcpy (license->ekpub, license_req->client_id, ntohl (license_req->be_ekpub_length));

		if((ret = os_sm2_sign((uint8_t*)license, sizeof(struct license),
					platform_privkey, platform_privkey_len, platform_pubkey, platform_pubkey_len, &sig, &siglen)) != 0) {
			printf("os_sm2_sign for license error (%d)\n", ret);
			goto out;
		}
		memcpy(license->signature, sig, siglen);

		ret = tcs_import_license(license);
		if(ret) {
			printf("[TPCM_ImportLicense Time: 0x%08x]ret: 0x%08x\n", (uint32_t)tv.tv_sec, ret);
			ret = -1;
		}
	}else{
		httc_util_dump_hex ("import license from file", license, sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
		printf("license_type    : %d\n", ntohl(license->be_license_type));
		printf("client_id_length: %d\n", ntohl(license->be_client_id_length));
		printf("tpcm_id_length  : %d\n", ntohl(license->be_tpcm_id_length));
		printf("host_id_length  : %d\n", ntohl(license->be_host_id_length));
		printf("ekpub_length    : %d\n", ntohl(license->be_ekpub_length));
		printf("signature_size  : %d\n", ntohl(license->be_signature_size));
		httc_util_time_print ("time_stamp      : %s\n", ntohll(license->be_time_stamp));
		httc_util_time_print ("be_deadline     : %s\n", ntohll(license->be_deadline));
		httc_util_dump_hex ("client_id", license->client_id, ntohl(license->be_client_id_length));
		httc_util_dump_hex ("tpcm_id", license->tpcm_id, ntohl(license->be_tpcm_id_length));
		httc_util_dump_hex ("host_id", license->host_id, ntohl(license->be_host_id_length));
		httc_util_dump_hex ("ekpub", license->ekpub, ntohl(license->be_ekpub_length));
		httc_util_dump_hex ("signature", license->signature, ntohl(license->be_signature_size));

		ret = tcs_import_license(license);
		if(ret) {
			printf("[TPCM_ImportLicense Time: 0x%08x]ret: 0x%08x\n", (uint32_t)tv.tv_sec, ret);
			ret = -1;
		}
		else
		{
			printf("tcs_import_license ok (%d)\n", ret);
		}
	}
out:
	if (sig)
	{
		SM2_FREE(sig);
		sig = NULL;
	}
	if (license)
	{
		httc_free (license);
		license = NULL;
	}
	return ret;
}

//import license_req,than export license file.
int export_license(struct license_req *license_req)
{
	int ret = 0;
	uint8_t *sig = NULL;
	uint32_t siglen = 0;
	struct timeval tv;
	uint8_t path[512] = {0};
	char license_str[(sizeof(struct license) + DEFAULT_SIGNATURE_SIZE) * 2 + 1] = {0};

	license = (struct license *)httc_malloc(sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
	if(license == NULL) {
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}

	if((ret = gettimeofday(&tv, NULL)) != 0) {
		perror("gettimeofday error");
		goto out;
	}

	license->be_license_type = license_req->be_license_type;
	license->be_client_id_length = license_req->be_client_id_length;
	license->be_tpcm_id_length = license_req->be_tpcm_id_length;
	license->be_host_id_length = license_req->be_host_id_length;
	license->be_ekpub_length = license_req->be_ekpub_length;
	license->be_signature_size = license_req->be_signature_size;
	license->be_time_stamp = license_req->be_time_stamp;
	license->be_deadline = htonll (tv.tv_sec + limit);
	memcpy (license->client_id, license_req->client_id, ntohl (license_req->be_client_id_length));
	memcpy (license->tpcm_id, license_req->tpcm_id, ntohl (license_req->be_tpcm_id_length));
	memcpy (license->host_id, license_req->host_id, ntohl (license_req->be_host_id_length));
	memcpy (license->ekpub, license_req->client_id, ntohl (license_req->be_ekpub_length));

	if((ret = os_sm2_sign((uint8_t*)license, sizeof(struct license),
				platform_privkey, platform_privkey_len, platform_pubkey, platform_pubkey_len, &sig, &siglen)) != 0) {
		printf("os_sm2_sign for license error (%d)\n", ret);
		goto out;
	}
	memcpy(license->signature, sig, siglen);

	httc_util_dump_hex ("export license to file", license, sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
	printf("license_type : %d\n", ntohl(license->be_license_type));
	printf("client_id_length : %d\n", ntohl(license->be_client_id_length));
	printf("tpcm_id_length : %d\n", ntohl(license->be_tpcm_id_length));
	printf("host_id_length : %d\n", ntohl(license->be_host_id_length));
	printf("ekpub_length : %d\n", ntohl(license->be_ekpub_length));
	printf("signature_size : %d\n", ntohl(license->be_signature_size));
	httc_util_time_print ("time_stamp : %s\n", ntohll(license->be_time_stamp));
	httc_util_time_print ("be_deadline : %s\n", ntohll(license->be_deadline));
	httc_util_dump_hex ("client_id", license->client_id, ntohl(license->be_client_id_length));
	httc_util_dump_hex ("tpcm_id", license->tpcm_id, ntohl(license->be_tpcm_id_length));
	httc_util_dump_hex ("host_id", license->host_id, ntohl(license->be_host_id_length));
	httc_util_dump_hex ("ekpub", license->ekpub, ntohl(license->be_ekpub_length));
	httc_util_dump_hex ("signature", license->signature, ntohl(license->be_signature_size));

	if (g_license_export)
	{
		binary_to_str((void *)license, license_str, sizeof(license_str));
		httc_util_dump_hex ("license", license, sizeof(struct license));
		if (license_path_export)
		{
			sprintf(path, "%s%s-authorized-1.license", license_path_export,license->tpcm_id);
			ret = httc_util_file_write( path, (const char *)license, (sizeof(struct license)+DEFAULT_SIGNATURE_SIZE) );
			if ( ret != (sizeof(struct license)+DEFAULT_SIGNATURE_SIZE) ){
				httc_util_pr_error ("httc_util_file_write error: %d != %d\n", ret, (int)(sizeof(struct license)+DEFAULT_SIGNATURE_SIZE) );
				ret = -1;
			}
			else
			{
				ret = 0;
			}
		}
		else
		{
			httc_util_pr_error ("httc_util_file_write error: file does not exist !\n");
		}
	}

out:
	if (sig)
	{
		SM2_FREE(sig);
	}
	if(license)
	{
		httc_free (license);
		license = NULL;
	}
	return ret;
}

int get_license_status(void)
{
	int ret = 0;
	int status = 0;
	int left = 0;
	uint32_t be_license_type = 0;
	uint32_t be_license_type_low = 0;
	uint32_t be_license_type_high = 0;

	if(0 != (ret = tcs_get_license_status(&status, &left))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf ("License status \n");
	printf ("status         : %d\n", status);
	be_license_type = status;
	be_license_type_low = be_license_type & 0x0000ffff;
	be_license_type_high = (be_license_type & 0xffff0000) >> 16;
	printf("license_type   : %d, license_type_low: %d, license_type_high: %d\n", be_license_type, be_license_type_low, be_license_type_high);
	if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
		if ((be_license_type_high == LICENSE_LTYPE_ZERO) && (be_license_type_low == LICENSE_LTYPE_ZERO)){
			printf("version        : %s\n", license_type_desc[LICENSE_LTYPE_ONE]);
		}
	else{
			printf("version        : %s\n", license_type_desc[be_license_type_high]);
		}
	}
	else
	{
		httc_util_pr_error ("Invalid version: %d\n", be_license_type_high);
	}
	printf ("left(days)     : %d\n", left);

	return 0;
}



int get_license_info(void)
{
	int ret = 0;
	int status = 0;
	uint64_t deadline = 0;
	uint32_t be_license_type = 0;
	uint32_t be_license_type_low = 0;
	uint32_t be_license_type_high = 0;

	if(0 != (ret = tcs_get_license_info(&status, &deadline))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf ("License status \n");
	printf ("status         : %d\n", status);
	be_license_type = status;
	be_license_type_low = be_license_type & 0x0000ffff;
	be_license_type_high = (be_license_type & 0xffff0000) >> 16;
	printf("license_type   : %d, license_type_low: %d, license_type_high: %d\n", be_license_type, be_license_type_low, be_license_type_high);
	if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
		printf("version        : %s\n", license_type_desc[be_license_type_low]);
	}
	else
	{
		httc_util_pr_error ("Invalid version: %d\n", be_license_type_high);
	}
	httc_util_time_print ("deadline       : %s\n", deadline);

	return 0;
}

int get_license_entity(void)
{
	int ret = 0;
	struct license_entity data[4] = {0};
	int num = 0;
	uint32_t be_license_type = 0;
	uint32_t be_license_type_low = 0;
	uint32_t be_license_type_high = 0;
    int i=0;

	if(0 != (ret = tcs_get_license_entity(data, &num))) {
		httc_util_pr_error ("ret: %d(0x%08x)\n", ret, ret);
		return -1;
	}

	printf("license_entity,num is: %d\n", num);
	for ( i; i < num; ++i)
	{
		be_license_type = ntohl(data[i].be_license_type);
		be_license_type_low = be_license_type & 0x0000ffff;
		be_license_type_high = (be_license_type & 0xffff0000) >> 16;
		printf("license_entity, i is : %d\n", i);
		printf("license_type         : %d, license_type_low: %d, license_type_high: %d\n", be_license_type, be_license_type_low, be_license_type_high);
		if ((be_license_type_high < LICENSE_LTYPE_MAX) && (be_license_type_high >= LICENSE_LTYPE_ZERO)){
			printf("version              : %s\n", license_type_desc[be_license_type_high]);
		}
		printf("client_id_length     : %d\n", ntohl(data[i].be_client_id_length));
		printf("tpcm_id_length       : %d\n", ntohl(data[i].be_tpcm_id_length));
		printf("host_id_length       : %d\n", ntohl(data[i].be_host_id_length));
		httc_util_time_print ("time_stamp           : %s\n", ntohll(data[i].be_time_stamp));
		httc_util_time_print ("deadline             : %s\n", ntohll(data[i].be_deadline));
		httc_util_dump_hex ("client_id", data[i].client_id, ntohl(data[i].be_client_id_length));
		httc_util_dump_hex ("tpcm_id", data[i].tpcm_id, ntohl(data[i].be_tpcm_id_length));
		httc_util_dump_hex ("host_id", data[i].host_id, ntohl(data[i].be_host_id_length));
	}

	return 0;
}


static void usage ()
{
	printf ("\n"
			" Usage: ./license [-a <licnese type> -v <licnese type> -f <path> -e <path> -T <time> -t <type> -n <node id> -H <Hdwaretag>] [-i <license>] -o <operation> -k <key>\n"
			"        -a <licnese type>	- The attr type\n"
			"        -v <licnese type>	- The version type\n"
			"        -f <path>			- The license_req path to export\n"
			"        -e <path>			- The license path to export\n"
			"        -T <time>			- The expiration time\n"
			"        -t <type>			- The license type,v2.0(1:test　2:TPCM　3:TPCM && TSB),v2.1(1:TPCM)\n"
			"        -c <client id>		- The node id\n"
			"        -H <host id>		- The host id\n"
			"        -i <licnese>		- The imported license path\n"
			"        -j <licnese_req>	- The imported license_req path\n"
			"        -o <operation>		- 0->LicenseRequest 1->LicenseImport 2->GetLicensestatus 3->GetLicenseInfo 4->GetLicenseEntity\n"
			"        -k <key>			- The privkey string + pubkey string\n"
			"    eg. ./license_tool -k 60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A -T 10000 -t 65537 -c 711d460257ae4d28f56d694d2cf173e44d76fbebeb41039bbcef9c45be73928dc4caf7926986341157c13c6711a86b0ac474c0fda62a86db373d1000bf15b984 -H 3145b5e92fd149db97264099c834c01c2da4abd188d13bddadf1e48c0323fee9 -o 0\n"
			"    eg. ./license_tool -i /opt/license -o 1\n"
			"    eg. ./license_tool -o 2\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	struct license_req *license_req = NULL;
	uint32_t tpcmRes = 0;
	int ch = 0;
	struct timeval lic_tv;

	uint8_t *Str = NULL;
  	uint32_t StrLen = 0;
	uint8_t *keyStr = NULL;
  	uint32_t keyStrLen = 0;
	uint32_t opt = 0;

	uint8_t data[1024] = {0};
	FILE *fp;
	struct stat fileStat;

	uint8_t *license_req_path = NULL;
	uint8_t *license_path = NULL;
	uint32_t licenseLen = sizeof (struct license) + DEFAULT_SIGNATURE_SIZE;
	uint32_t license_req_len = sizeof (struct license_req);

	if(argc < 3){
		usage ();
		return -EINVAL;
	}

	license_req = (struct license_req *)httc_calloc(1, sizeof(struct license_req) + DEFAULT_SIGNATURE_SIZE);
	if(license_req == NULL) {
		printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
		return -ENOMEM;
	}
	license_req->be_license_type = 0;

	while ((ch = getopt(argc, argv, "a:v:f:e:T:t:c:H:i:j:k:o:h")) != -1)
	{
		switch (ch)
		{
			case 'a':
				license_type = atoi(optarg);
				break;
			case 'v':
				license_stype = atoi(optarg);
				break;
			case 'f':	//export license req file.
				license_path_out = optarg;
				g_file_type = 1;
				break;
			case 'e':	//export license file.
				license_path_export = optarg;
				g_license_export = 1;
				break;
			case 'T':
				limit = atoi(optarg);
				break;
			case 't':
				license_req->be_license_type = atoi(optarg);
				break;
			case 'c':
				Str = optarg;
				StrLen = strlen(Str);
				if(StrLen != (MAX_CLIENT_ID_SIZE * 2)){
					printf ("[%s:%d] client id error! StrLen is: %d \n", __func__, __LINE__, StrLen);
					usage ();
					return -EINVAL;
				}
				httc_util_str2array((uint8_t *)license_req->client_id, Str, StrLen);
				license_req->be_client_id_length = MAX_CLIENT_ID_SIZE;
				break;
			case 'H':
				Str = optarg;
				StrLen = strlen(Str);
				if(StrLen != (MAX_HOST_ID_SIZE * 2)){
					printf ("[%s:%d] host id error! StrLen is: %d \n", __func__, __LINE__, StrLen);
					usage ();
					return -EINVAL;
				}
				httc_util_str2array((uint8_t *)license_req->host_id, Str, StrLen);
				license_req->be_host_id_length = MAX_HOST_ID_SIZE;
				break;
			case 'i':	//import license file.
				license_path = optarg;

				license = (struct license *)httc_malloc(sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
				if(license == NULL) {
					printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
					return TSS_ERR_NOMEM;
				}

				if (NULL == (fp = fopen (license_path, "rb")))
				{
					perror ("Open license file faliure");
					ret = -1;
					return ret;
				}

				stat (license_path, &fileStat);
				if(licenseLen != (uint32_t)fileStat.st_size)
				{
					printf ("License file size error\n");
					ret = -1;
					return ret;
				}
				if (licenseLen != fread(data,1,licenseLen,fp))
				{
					perror ("Read license file faliure");
					fclose(fp);
					ret = -1;
					return ret;
				}
				memcpy(license,data,licenseLen);
				fclose(fp);
				break;
			case 'j':	//import license_req file.
				license_req_path = optarg;

				g_license_req = (struct license_req *)httc_malloc(sizeof(struct license_req) + DEFAULT_SIGNATURE_SIZE);
				if(g_license_req == NULL) {
					printf ("[%s:%d] Req Alloc error!\n", __func__, __LINE__);
					return TSS_ERR_NOMEM;
				}

				if (NULL == (fp = fopen (license_req_path, "rb")))
				{
					printf ("[%s:%d] Open license req file[%s] failed!\n", __func__, __LINE__,license_req_path);
					perror ("Open license req file faliure");
					ret = -1;
					return ret;
				}

				stat (license_req_path, &fileStat);
				if(license_req_len != (uint32_t)fileStat.st_size)
				{
					printf ("License file size error,st_size=%d,license_req_len=%d \n",(uint32_t)fileStat.st_size,license_req_len);
					ret = -1;
					return ret;
				}
				if (license_req_len != fread(data,1,license_req_len,fp))
				{
					perror ("Read license file faliure");
					fclose(fp);
					ret = -1;
					return ret;
				}
				memcpy(g_license_req,data,license_req_len);
				fclose(fp);
				break;
			case 'k':
				keyStr = optarg;
				keyStrLen = strlen(keyStr);
				if ((TPCM_PRIVKEY_STR_LEN + TPCM_PUBKEY_STR_LEN) != keyStrLen){
					printf ("Invalid key string!\n");
					return -1;
				}
				httc_util_str2array (platform_privkey, keyStr, TPCM_PRIVKEY_STR_LEN);
				httc_util_dump_hex ((const char *)"privkey", platform_privkey, platform_privkey_len);
				httc_util_str2array (platform_pubkey, keyStr + TPCM_PRIVKEY_STR_LEN, TPCM_PUBKEY_STR_LEN);
				httc_util_dump_hex ((const char *)"pubkey", platform_pubkey, platform_pubkey_len);
				break;
			case 'o':
				opt = atoi(optarg);
				if(opt == 0) ret = license_request(license_req);
				if(opt == 1) ret = import_license(license_req);
				if(opt == 2) ret = get_license_status();
				if(opt == 3) ret = get_license_info();
				if(opt == 4) ret = get_license_entity();
				if(opt == 5) ret = export_license(g_license_req);
				break;
			case 'h':
			default:
				usage ();
				return -EINVAL;
		}
	}
	if(license_req) httc_free(license_req);
	return ret;
}


