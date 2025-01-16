#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "tcmkeys.h"
#include "tcmutil.h"
#include "tcmfunc.h"
#include "tcm_constants.h"
#include "crypto/sm/sm2_if.h"

#include "mem.h"
#include "sys.h"
#include "file.h"
#include "debug.h"
#include "convert.h"
#include "transmit.h"
#include "tpcm_command.h"
#include "tcs_config.h"
#include "tcs_attest.h"
#include "tcs_error.h"
#include "tutils.h"
#include "tcs_util_policy_update.h"
#include "tcs_attest_def.h"

#pragma pack(push, 1)

typedef struct {
	RESPONSE_HEADER;
	uint32_t status;
}get_trusted_status_rsp_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t length;
	uint8_t  data[0];
}tpcm_id_rsp_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t feature;
}tpcm_feature_rsp;

typedef struct {
    RESPONSE_HEADER;
    uint32_t uiSize;
    uint8_t  uaPubkey[0];
}get_tpcm_pik_pub_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiKeyHandle;
}set_tpcm_pik_req_st;

typedef struct{	
	uint32_t ilegal_program_load;
	uint32_t ilegal_lib_load;
	uint32_t ilegal_kernel_module_load;
	uint32_t ilegal_file_access;
	uint32_t ilegal_device_access;
	uint32_t ilegal_network_inreq;
	uint32_t ilegal_network_outreq;
	uint32_t process_code_measure_fail;
	uint32_t kernel_data_measure_fail;
	uint32_t kernel_code_measure_fail;
}trust_input_info;

typedef struct{
	COMMAND_HEADER;
	uint64_t host_report_time;
	uint64_t host_startup_time;
	unsigned char host_id[MAX_HOST_ID_SIZE];
	uint32_t uiHostIp;
	trust_input_info info;
	uint64_t Nonce;
}tcs_req_generate_trust_report;


typedef struct{
	RESPONSE_HEADER;
	struct trust_report report;
}tcs_rsp_generate_trust_report;

typedef struct {
	COMMAND_HEADER;
	uint64_t be_host_time;
}get_tpcm_info_req;

typedef struct {
	RESPONSE_HEADER;
	struct tpcm_info tpcm_info;
}get_tpcm_info_rsp;

typedef struct{
	COMMAND_HEADER;
	uint64_t Nonce;
	unsigned char host_id[MAX_HOST_ID_SIZE];
	uint8_t  attached_hash[DEFAULT_HASH_SIZE];
}tcs_req_generate_trust_evidence;


typedef struct{
	RESPONSE_HEADER;
	struct trust_evidence evi;
}tcs_rsp_generate_trust_evidence;

typedef struct get_replay_counter_rsp{
	RESPONSE_HEADER;
	uint64_t replay_counter;
}get_replay_counter_rsp_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t num;
	struct policy_version data[0];
}get_policies_version_rsp_st;

typedef struct {
	COMMAND_HEADER;
	uint32_t be_type;
}sync_trust_status_req;

typedef struct{
	COMMAND_HEADER;
	uint32_t uimaxlength;
}get_tpcmlog_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiLogNumber;
	uint8_t uaLog[0];
}get_tpcmlog_rsp_st;
#pragma pack(pop)

#define HTTC_HOST_ID_FILE		HTTC_TSS_CONFIG_PATH"host.id"
#define HTTC_REMOTE_CERT_PATH	HTTC_TSS_CONFIG_PATH"remote-cert"

int tcs_get_dmeasure_trust_status(uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_trusted_status_rsp_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl (TSS_ORD_GetDmeasureTrustedStatus);
	rsp = (get_trusted_status_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_trusted_status_rsp_st)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
	}
	
out:	
	if(buffer) {
		httc_free (buffer);
	}
	return ret;
}

int tcs_get_intercept_trust_status(uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_trusted_status_rsp_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl (TSS_ORD_GetInterecpetTrustedStatus);
	rsp = (get_trusted_status_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_trusted_status_rsp_st)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
	}
	
out:	
	if(buffer) {
		httc_free (buffer);
	}
	return ret;
}

int tcs_get_trust_status(uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_trusted_status_rsp_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetTrustedStatus);
	rsp = (get_trusted_status_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_trusted_status_rsp_st)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
	}
	
out:	
	if(buffer) {
		httc_free (buffer);
	}
	return ret;
}

int tcs_sync_trust_status(uint32_t type)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	sync_trust_status_req *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (sync_trust_status_req *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof(sync_trust_status_req);	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SyncTrustedStatus);	
	cmd->be_type = htonl(type);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	ret = tpcmRspRetCode(rsp);
out:	
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}


int tcs_get_tpcm_id(unsigned char *id, int *len_inout)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_id_rsp_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetMark);
	rsp = (tpcm_id_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != (sizeof (tpcm_id_rsp_st) + ntohl(rsp->length))) {
			httc_util_pr_error("Invalid response length (%d != %d)\n",
				tpcmRspLength(rsp), (int)(sizeof (tpcm_id_rsp_st) + ntohl(rsp->length)));
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}

		if((int)(*len_inout) < (int)ntohl(rsp->length)) {
			httc_util_pr_error("out space is not enough (%d < %d)\n", *len_inout, (int)ntohl(rsp->length));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}

		*len_inout = ntohl (rsp->length);
		memcpy (id, rsp->data, *len_inout);
	}

out:
	if(buffer) {
		httc_free(buffer);
	}

	return ret;
}

void itoc(uint32_t src, char *dst)
{
        if((src >=0) && (src<= 9))      {
                *dst = '0' + src - 0;
        }else if ((src >= 0xa) && (src <= 0xf)){
                *dst = 'a' + src - 0xa;
        }
}

void httc_util_str2hex (char *src, char *dst, int dst_len)
{
         unsigned int i;
         for (i=0; i<dst_len/2; i++) {
                itoc((uint32_t)((src[i]>>4)&0xf), &dst[i * 2]);
                itoc((uint32_t)((src[i])&0xf), &dst[i * 2 + 1]);
         }
}

int tcs_get_host_id(unsigned char *id,int *len_inout){

	char *data = NULL;
	unsigned char id_entry[MAX_HOST_ID_SIZE/2] = {0};
	unsigned long host_id_len = 0;

	if(id == NULL || len_inout == NULL) return TSS_ERR_PARAMETER;
	
	if ((*len_inout) < MAX_HOST_ID_SIZE){
		httc_util_pr_error ("No enough space for id (%d < %d)\n", *len_inout, MAX_HOST_ID_SIZE);
		return TSS_ERR_OUTPUT_EXCEED;
	}

	if (0 == httc_util_file_size (HTTC_HOST_ID_FILE, &host_id_len)){
		if (0 != (data = httc_util_file_read_full (HTTC_HOST_ID_FILE, &host_id_len))){
			memcpy (id, data, host_id_len);
			*len_inout = host_id_len;
			httc_free (data);
			return TSS_SUCCESS;
		}
	}else{
		httc_util_rand_bytes (id_entry, MAX_HOST_ID_SIZE/2 );
		 httc_util_str2hex((char *)id_entry, (char *)id, MAX_HOST_ID_SIZE);
		*len_inout = MAX_HOST_ID_SIZE;
		if (httc_util_create_path_of_fullpath (HTTC_HOST_ID_FILE)){
			httc_util_pr_error ("Create host id path error!\n");
			return TSS_ERR_FILE;
		}
		if (*len_inout != httc_util_file_write (HTTC_HOST_ID_FILE, (const char*)id, *len_inout)){
			httc_util_pr_error ("Write host id file error!\n");
			return TSS_ERR_FILE;
		}
	}
	
	return TSS_SUCCESS;
}

int tcs_set_host_id(unsigned char *id,int len)
{
		if (httc_util_create_path_of_fullpath (HTTC_HOST_ID_FILE)){
			httc_util_pr_error ("Create host id path error!\n");
			return TSS_ERR_FILE;
		}
		if (len != httc_util_file_write (HTTC_HOST_ID_FILE, (const char*)id, len)){
			httc_util_pr_error ("Write host id file error!\n");
			return TSS_ERR_FILE;
		}
		return TSS_SUCCESS;
}

int tcs_get_tpcm_features(uint32_t *features)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_feature_rsp *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTpcmFeature);
	rsp = (tpcm_feature_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) 	goto out;

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(tpcm_feature_rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*features = ntohl(rsp->feature);
	}

out:	
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_get_pik_pubkey(unsigned char *pubkey, int *len_inout)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_tpcm_pik_pub_rsp_st *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof (tpcm_req_header_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTpcmPikPubkey);
	rsp = (get_tpcm_pik_pub_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if((int)(tpcmRspLength(rsp) - sizeof(get_tpcm_pik_pub_rsp_st)) > (int)(*len_inout)) {
			httc_util_pr_error("data space is not enough (%d < %d)\n", *len_inout, 
							(int)(tpcmRspLength(rsp) - sizeof(get_tpcm_pik_pub_rsp_st)));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*len_inout = tpcmRspLength(rsp) - sizeof(get_tpcm_pik_pub_rsp_st);
		memcpy(pubkey, rsp->uaPubkey, *len_inout);
	}

out:
	if(buffer) {
		httc_free (buffer);
	}
	
	return ret;
}

/*
 * 设置tpcm身份密钥
 */
int tcs_set_tpcm_pik(uint32_t keyhandle)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	set_tpcm_pik_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if(NULL == (buffer = httc_malloc(CMD_DEFAULT_ALLOC_SIZE))) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (set_tpcm_pik_req_st *)buffer;
	cmdLen = sizeof(set_tpcm_pik_req_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SetTpcmPik);
	cmd->uiKeyHandle = htonl(keyhandle);
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	ret = tpcmRspRetCode(rsp);

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_generate_tpcm_pik(unsigned char *passwd)
{
	uint32_t ret;
	char *ownerPwd = (char *)passwd;
	char *smkPwd = "httc@123";
	char *pikPwd = "httc@123";
	uint8_t ownerAuth[32] = {0};
	uint8_t smkAuth[32] = {0};
	uint8_t pikAuth[32] = {0};
	char *label = "abc";
	uint8_t labelAuth[32] = {0};
	keydata keyparms;
	keydata idkey;
	uint32_t keyHandle;
	uint8_t idkeyblob[4096] = {0}; /* area to hold key blob */
	unsigned int  idkeybloblen = 0; /* key blob length */
	TCM_SYMMETRIC_KEY_PARMS params;
	uint32_t idBindingBufferSize = 1024;
	uint8_t idBindingBuffer[idBindingBufferSize];
	TCM_PCR_INFO pcrInfo;
	TCM_PCR_COMPOSITE pcrComp;
	STACK_TCM_BUFFER(keyparamsbuf);
	STACK_TCM_BUFFER(serPcrInfo);

	TCM_setlog(0);

	memset(&keyparms, 0x0, sizeof(keyparms));
	memset(&idkey, 0x0, sizeof(idkey));
	memset(&params, 0x0, sizeof(TCM_SYMMETRIC_KEY_PARMS));
	memset(&pcrInfo, 0x0, sizeof(pcrInfo));
	memset(&pcrComp, 0x0, sizeof(pcrComp));

	TSS_sm3(ownerPwd, strlen(ownerPwd), ownerAuth);
	TSS_sm3(smkPwd, strlen(smkPwd), smkAuth);
	TSS_sm3(pikPwd, strlen(pikPwd), pikAuth);
	TSS_sm3(label, strlen(label), labelAuth);

	pcrInfo.tag = TCM_TAG_PCR_INFO;
	pcrInfo.localityAtCreation = TCM_LOC_ZERO;
	pcrInfo.localityAtRelease = TCM_LOC_ZERO;
	pcrInfo.PcrAtRelease.sizeOfSelect = 4;
	pcrInfo.PcrAtCreation.sizeOfSelect = 4;

	if(0 != (ret = TCM_Open())) goto out;
	ret = TCM_WritePCRInfo(&serPcrInfo, &pcrInfo);
	if(ret & ERR_MASK) {
		httc_util_pr_error("Error while serializing PCRInfo.\n");
		goto out;
	}

	keyparms.pub.pcrInfo.size = ret;
	memcpy(keyparms.pub.pcrInfo.buffer, serPcrInfo.buffer, serPcrInfo.used);	

	keyparms.hdr.key12.tag = TCM_TAG_KEY;
	keyparms.hdr.key12.fill = 0;
	keyparms.keyUsage = TCM_SM2KEY_IDENTITY;
	keyparms.pub.algorithmParms.algorithmID= TCM_ALG_SM2;
	keyparms.keyFlags = 0;
	keyparms.keyFlags &= ~TCM_KEY_FLG_MIGRATABLE; /** not MIGRATABLE */
	keyparms.pub.algorithmParms.encScheme = TCM_ES_SM2NONE;
	keyparms.pub.algorithmParms.sigScheme = TCM_SS_SM2;
	keyparms.pub.algorithmParms.parmSize = 4;
	keyparms.pub.algorithmParms.sm4para.keyLength =256;
	keyparms.encData.size = 0;
	keyparms.authDataUsage = TCM_AUTH_ALWAYS;
	
	if(0 != (ret = TCM_MakeIdentity(pikAuth, labelAuth,
			&keyparms, &idkey, idkeyblob, &idkeybloblen,
			smkAuth, ownerAuth, idBindingBuffer, &idBindingBufferSize, NULL))) {
		httc_util_pr_error("MakeIdentity returned error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
		goto out;
	}
	
	if(0 != (ret = TCM_LoadKey(0x40000000, smkAuth, &idkey, &keyHandle))) {
		httc_util_pr_error("LoadKey returned error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
		goto out;
	}
	
	if(0 != (ret = TCM_GetPubKey(keyHandle, pikAuth, &keyparms.pub))) {
		httc_util_pr_error("GetPubKey returned error '%s' (%d).\n", TCM_GetErrMsg(ret), ret);
		goto out;
	}
	TCM_Close();
	
	ret = tcs_set_tpcm_pik(keyHandle);
	if(ret) {
		httc_util_pr_error("[tcs_set_tpcm_pik] ret: 0x%08x\n", ret);
	}
	return ret;
out:
	TCM_Close();
	return ret;
}
/*
 * 	生成可信报告
 */
int tcs_get_ruida_ip(uint32_t *hostip, uint32_t *num){
	
	int ret = 0,i=0;
	char *aaddr = NULL;
	struct ifaddrs *addrs, *head;
	// uint32_t hostip = 0;
	*num=0;

/*Get host ip*/	
	getifaddrs(&addrs);
	head = addrs;
	do {
			if(head->ifa_addr == NULL)
				continue;
			if (head->ifa_addr->sa_family != AF_INET)
				continue;
			aaddr = inet_ntoa(((struct sockaddr_in *) head->ifa_addr)->sin_addr);
			if((!strcmp(head->ifa_name,"lo") && !strcmp(aaddr,"127.0.0.1"))|| !strcmp(head->ifa_name,"virbr0"))
				continue;
			if(!strncmp(aaddr,"192",3)|| !strncmp(aaddr,"172",3))
			{
				hostip[i] = ((struct sockaddr_in *) head->ifa_addr)->sin_addr.s_addr;
				i++;
 				*num=i;
				printf("tcs_get_ruida_ip:*num:%d\r\n",*num);
			}else{
				continue;
			}
			if(*num>=10)
			{
				break;
			}     	
    } while ((head = head->ifa_next));
	if(addrs) freeifaddrs(addrs);
	return ret;
}
/*
 * 	生成可信报告
 */
int tcs_generate_trust_report(struct trust_report *report, uint64_t nonce,unsigned char *host_id,uint32_t be_addr){
	
	int ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmdlen = 0;
	char *aaddr = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_req_generate_trust_report *req = NULL;
	tcs_rsp_generate_trust_report *rsp = NULL;
	struct timeval tv;
	struct timezone tz;	
	struct ifaddrs *addrs, *head;
	uint32_t hostip = 0;

	if(report == NULL || host_id == NULL) return TSS_ERR_PARAMETER;
	
	/*Get host ip*/	
	getifaddrs(&addrs);
    head = addrs;


    do {
	     if(be_addr!=0)
	     {

               hostip=be_addr;
	       httc_util_pr_info("====break=====hostip:%d htonl(hostip):%d\r\n",hostip,htonl(hostip));
		break;
	      }	     
	    if(head->ifa_addr == NULL)
			continue;
		if (head->ifa_addr->sa_family != AF_INET)
			continue;
        aaddr = inet_ntoa(((struct sockaddr_in *) head->ifa_addr)->sin_addr);
		if((!strcmp(head->ifa_name,"lo") && !strcmp(aaddr,"127.0.0.1"))|| !strcmp(head->ifa_name,"virbr0"))
        	continue;
		hostip = ((struct sockaddr_in *) head->ifa_addr)->sin_addr.s_addr;
    } while ((head = head->ifa_next));
	
	if (NULL == (cmd = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto out;

	}
	
	req = (tcs_req_generate_trust_report *)cmd;
	rsp = (tcs_rsp_generate_trust_report *)(cmd + CMD_DEFAULT_ALLOC_SIZE/2);
		
	gettimeofday(&tv,&tz);
	req->host_report_time = htonll(tv.tv_sec);	
	memcpy(req->host_id,host_id, MAX_HOST_ID_SIZE);
	req->uiHostIp = htonl(hostip);	
	req->Nonce = htonll(nonce);

	cmdlen = sizeof(tcs_req_generate_trust_report);
	req->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	req->uiCmdLength = cmdlen;
	req->uiCmdCode = TPCM_ORD_GetTrustedCredential;
	
	if (0 != (ret = tpcm_transmit (cmd, cmdlen, rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if(tpcmRspRetCode(rsp)){
		ret = tpcmRspRetCode(rsp);
		goto out;
	}	

	if (tpcmRspLength (rsp) == sizeof (tcs_rsp_generate_trust_report)){
		memcpy(report,&rsp->report,sizeof(struct trust_report));	
	}
	else{
		httc_util_pr_error ("result is not enough (%d < %ld)\n", 
										tpcmRspLength (rsp), 
										(long int)sizeof(tcs_rsp_generate_trust_report));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode (rsp);	
	
out:
	if(cmd) httc_free(cmd);
	if(addrs) freeifaddrs(addrs);
	return ret;
}

int tcs_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid)
{
	int r;
    int i = 0;
    int number = 0;
    struct remote_cert *cert = NULL;
    struct remote_cert *cert_list = NULL;

	if (strlen ((const char*)oid) != MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("Invalid oid\n");
		return TSS_ERR_PARAMETER;
	}

    if ((r = tcs_get_remote_certs(&cert_list, &number))){
    	httc_util_pr_error ("tcs_get_remote_certs error :%d(0x%x)\n", r, r);
		return r;
	}

    for(i = 0;i < number; i++){
		if (!memcmp ((const char *)cert_list[i].id, (const char *)oid, MAX_TPCM_ID_SIZE)){
			cert = cert_list + i;
			break;
		}
    }
	if (!cert){
		httc_util_pr_error ("No matched cert\n");
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	if (os_sm2_verify ((const uint8_t *)report, sizeof (struct trust_report) - DEFAULT_SIGNATURE_SIZE,
			cert->cert, ntohl (cert->be_length), report->signature, DEFAULT_SIGNATURE_SIZE)){
		if (cert_list) httc_free (cert_list);
		httc_util_pr_error ("SM2 Verify trust evidence failed\n");
		return TSS_ERR_VERIFY;
	}

	if (nonce != ntohll (report->be_nonce)){
		httc_util_pr_error ("Dismatched nonce (%lx != %lx)\n", (long int)nonce, (long int)ntohll (report->be_nonce));
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_NONCE;
	}

	if (100 != ntohl (report->content.be_eval)){
		httc_util_pr_error ("Untrusted report\n");
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_UNTRUSTED;
	}
	
	if (cert_list) httc_free (cert_list);
	return TSS_SUCCESS;
}

int tcs_get_tpcm_info(struct tpcm_info *info)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	get_tpcm_info_req *cmd = NULL;
	get_tpcm_info_rsp *rsp = NULL;
	struct timeval tv;
	
	if((ret = gettimeofday(&tv, NULL)) != 0) {
		httc_util_pr_error("Get time failed!\n");
		return ret;
	}

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (get_tpcm_info_req *)buffer;
	cmdLen = sizeof(get_tpcm_info_req);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTPCMStatus);
	cmd->be_host_time = htonll (tv.tv_sec);
	
	rsp = (get_tpcm_info_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if((int)(tpcmRspLength(rsp) - sizeof (tpcm_req_header_st)) != sizeof(struct tpcm_info)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy(info, &(rsp->tpcm_info), sizeof(struct tpcm_info));
	}

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_get_tdd_info(struct tdd_info *info)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	get_tdd_info_req *cmd = NULL;
	get_tdd_info_rsp *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (get_tdd_info_req *)buffer;
	cmdLen = sizeof(get_tdd_info_req);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTddStatus);
	
	rsp = (get_tdd_info_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		httc_util_pr_error("get rsp tag(0x%02X), tag:%d, len:0x%02X, len:%d, ret = %d \n", tpcmRspTag(rsp), tpcmRspTag(rsp), tpcmRspLength(rsp), tpcmRspLength(rsp), ret);
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if((int)(tpcmRspLength(rsp) - sizeof (tpcm_rsp_header_st)) != sizeof(struct tdd_info)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy(info, &(rsp->info), sizeof(struct tdd_info));
	}

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

/*
 * 	生成可信证明
 */
int tcs_generate_trust_evidence(struct trust_evidence *evidence,
		uint64_t nonce,	unsigned char *host_id, uint8_t *attached_hash){

	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *cmd = NULL;
	tcs_req_generate_trust_evidence *req = NULL;
	tcs_rsp_generate_trust_evidence *rsp = NULL;

	if(evidence == NULL || host_id == NULL || attached_hash == NULL) return TSS_ERR_PARAMETER;

	if((cmd = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req = (tcs_req_generate_trust_evidence *)cmd;
	rsp = (tcs_rsp_generate_trust_evidence *)(cmd + CMD_DEFAULT_ALLOC_SIZE / 2);

	req->Nonce = htonll(nonce);
	memcpy(req->host_id,host_id,MAX_HOST_ID_SIZE);
	memcpy(req->attached_hash,attached_hash,DEFAULT_HASH_SIZE);
	
	cmdLen = sizeof(tcs_req_generate_trust_evidence);
	req->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl(cmdLen);
	req->uiCmdCode = htonl(TPCM_ORD_GetTrustedEvidence);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if(tpcmRspRetCode(rsp)){
		ret = tpcmRspRetCode(rsp);
		goto out;
	}
	if (tpcmRspLength (rsp) != sizeof (tcs_rsp_generate_trust_evidence)){
		httc_util_pr_error ("Invalid response stream!\n");	
	}
	memcpy(evidence,&rsp->evi,sizeof(struct trust_evidence));
	ret = tpcmRspRetCode (rsp);	
	
out:	
	if(cmd) httc_free(cmd);
	return ret;
}
int tcs_verify_trust_evidence (struct trust_evidence *evidence, uint64_t nonce, unsigned char *oid)
{
	int r;
    int i = 0;
    int number = 0;
    struct remote_cert *cert = NULL;
    struct remote_cert *cert_list = NULL;

	if (strlen ((const char *)oid) != MAX_TPCM_ID_SIZE){
		httc_util_pr_error ("Invalid oid\n");
		return TSS_ERR_PARAMETER;
	}

    if ((r = tcs_get_remote_certs(&cert_list, &number))){
    	httc_util_pr_error ("tcs_get_remote_certs error :%d(0x%x)\n", r, r);
		return r;
	}

    for (i = 0; i < number; i++){
		if (!memcmp ((const char *)cert_list[i].id, (const char *)oid, MAX_TPCM_ID_SIZE)){
			cert = cert_list + i;
			break;
		}
    }

	if (!cert){
		httc_util_pr_error ("No matched cert\n");
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	if (os_sm2_verify ((const uint8_t *)evidence, sizeof (struct trust_evidence) - DEFAULT_SIGNATURE_SIZE,
			cert->cert, ntohl (cert->be_length), evidence->signature, DEFAULT_SIGNATURE_SIZE)){
		if (cert_list) httc_free (cert_list);
		httc_util_pr_error ("SM2 Verify trust evidence failed\n");
		return TSS_ERR_VERIFY;
	}

	if (nonce != ntohll (evidence->be_nonce)){
		httc_util_pr_error ("Dismatched nonce (%lx != %lx)\n", (long int)nonce, (long int)ntohll (evidence->be_nonce));
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_NONCE;
	}

	if (100 != ntohl (evidence->be_eval)){
		httc_util_pr_error ("Untrusted evidence\n");
		if (cert_list) httc_free (cert_list);
		return TSS_ERR_UNTRUSTED;
	}

	if (cert_list) httc_free (cert_list);
	return TSS_SUCCESS;
}

/*
 * 	与对端进行远程证明
 */
int tcs_remote_attest (const char *peer)
{
	return 0;
}

/*添加远程信任的证书*/
int tcs_add_remote_cert (struct remote_cert *remote_cert)
{
	int r = 0;
    char file_name[256] = {0};
	char id[MAX_TPCM_ID_SIZE+1] = {0};
	memcpy (id, remote_cert->id, MAX_TPCM_ID_SIZE);

	if (!is_tpcm_id_valid ((const char *)id)){
		httc_util_pr_error ("Invalid tpcm cert id!\n");
		return TSS_ERR_PARAMETER;
	}
    sprintf (file_name, "%s/%s.cert", HTTC_REMOTE_CERT_PATH, id);

	if ((r = httc_util_create_path (HTTC_REMOTE_CERT_PATH))){
			httc_util_pr_error ("mkdir %s error: %d\n", HTTC_REMOTE_CERT_PATH, r);
			return TSS_ERR_DIR;
	}
	
	r = httc_util_file_write(file_name, (char *)remote_cert, sizeof(struct remote_cert));
    if (r != sizeof(struct remote_cert)){
		httc_util_pr_error ("httc_util_file_write error: %d\n", r);
		return TSS_ERR_WRITE;
	}
    return 0;
}

/*
 *删除信任的远程证书
 *
 * */
int tcs_remove_remote_cert(const char *id)
{
	int r;
	DIR *dir = NULL;
    struct dirent *dirent;
	char path_name[MAX_PATH_LENGTH] = {0};
	int found = 0; //添加一个标志来跟踪是否找到了匹配项

    if((dir = opendir(HTTC_REMOTE_CERT_PATH)) == NULL){
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	if (!is_tpcm_id_valid (id)){
		httc_util_pr_error ("Invalid tpcm cert id!\n");
		closedir(dir);
		return TSS_ERR_PARAMETER;
	}

	while(1){
		if (NULL == (dirent = readdir(dir))) break;
		if (strstr (dirent->d_name, id)){
			snprintf (path_name, MAX_PATH_LENGTH, "%s/%s.cert", HTTC_REMOTE_CERT_PATH, id);
			if ((r = remove ((const char *)path_name))){
				closedir(dir);
				return TSS_ERR_FILE;
			}
			found = 1; //标记找到了匹配项
			break;
		}
	}
	closedir (dir);

	return found ? TSS_SUCCESS : TSS_ERR_ITEM_NOT_FOUND; //根据是否找到匹配项返回相应的错误代码
}

/*
 *获取信任的远程证书列表
 *
 * */
int tcs_get_remote_certs(struct remote_cert **remote_cert,int *number)
{
	int i = 0;
	int total = 0;
	unsigned long size = 0;
	DIR *dir = NULL;
    struct dirent *dirent;
	struct remote_cert *cert = NULL;
	struct remote_cert *cert_list = NULL;
    char path_name[MAX_PATH_LENGTH] = {0};

	*remote_cert = NULL;
	*number = 0;
	
    if((dir = opendir(HTTC_REMOTE_CERT_PATH)) == NULL){
		httc_util_pr_dev ("opendir(%s) failed!\n", HTTC_REMOTE_CERT_PATH);
		return TSS_SUCCESS;
	}
	while ((dirent = readdir(dir))){
		if (!strstr (dirent->d_name, ".cert")) continue;
		total ++;
	}
	closedir (dir);
	dir = NULL;

    if(NULL == (cert_list = (struct remote_cert *)httc_malloc((total * sizeof(struct remote_cert))))){
        httc_util_pr_error ("No mem for remote cert!\n");
        return TSS_ERR_NOMEM;
    }
	
    if((dir = opendir(HTTC_REMOTE_CERT_PATH)) == NULL){
		httc_util_pr_error ("opendir(%s) failed!\n", HTTC_REMOTE_CERT_PATH);
		httc_free (cert_list);
		return TSS_SUCCESS;
	}
	while ((dirent = readdir(dir))){
		if (!strstr (dirent->d_name, ".cert")) continue;
		sprintf(path_name, "%s/%s", HTTC_REMOTE_CERT_PATH, dirent->d_name);
		cert = httc_util_file_read_full(path_name, &size);
		if (!cert || (size != sizeof (struct remote_cert))){
			closedir (dir);
			httc_free (cert_list);
			return TSS_ERR_FILE;
		}
		memcpy (&cert_list[i++], cert, sizeof (struct remote_cert));
		httc_free (cert);
		(*number) ++;
	}
	if (dir) closedir (dir);
	*remote_cert = cert_list;
    return 0;
} 

int tcs_get_replay_counter_from_tpcm (uint64_t *replay_counter)
{
	int ret = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_req_header_st *cmd = NULL;
	uint64_t replay_trans = 0;
	struct get_replay_counter_rsp *rsp = NULL;

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (struct get_replay_counter_rsp*)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (sizeof (tpcm_req_header_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_GetReplayCounter);

	if (0 != (ret = tpcm_transmit (cmd, sizeof (tpcm_req_header_st), rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (struct get_replay_counter_rsp) != tpcmRspLength (rsp)){
			httc_util_pr_error ("Invalid response steam.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		replay_trans = ntohll (rsp->replay_counter);
		memcpy(replay_counter,&replay_trans,sizeof(uint64_t));
	}

out:
	if (cmd)	httc_free (cmd);
	return ret;
}

int tcs_get_replay_counter (uint64_t *replay_counter)
{
	int r;
	uint64_t tpcm_replay = 0;
	uint64_t local_replay = 0;

	if((r = tcs_get_replay_counter_from_tpcm (&tpcm_replay))) {
		httc_util_pr_error("[tcs_get_replay_counter_from_tpcm] r: 0x%08x\n", r);
		return r;
	}
	httc_util_pr_dev("tpcm_replay: %llu(0x%llx)\n", (unsigned long long)tpcm_replay, (unsigned long long)tpcm_replay);

	if((r = tcs_util_read_replay_counter (&local_replay))) {
		httc_util_pr_error("[tcs_get_replay_counter_from_tpcm] r: 0x%08x\n", r);
		return r;
	}
	httc_util_pr_dev("local_replay: %llu(0x%llx)\n", (unsigned long long)local_replay, (unsigned long long)local_replay);
	*replay_counter = MAX (tpcm_replay, local_replay);
	
	return r;
}

int tcs_get_policies_version_from_tpcm (struct policy_version *version, int *num_inout){
	
	int ret = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_req_header_st *cmd = NULL;
	get_policies_version_rsp_st *rsp = NULL;

	if(version == NULL || num_inout == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (get_policies_version_rsp_st*)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (sizeof (tpcm_req_header_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_GetPoliciesVersion);

	if (0 != (ret = tpcm_transmit (cmd, sizeof (tpcm_req_header_st), rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (get_policies_version_rsp_st) > tpcmRspLength (rsp)){
			httc_util_pr_error ("Response steam error.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}

		memcpy(version,rsp->data,(*num_inout) * sizeof(struct policy_version));
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;
}


int tcs_get_policies_version (struct policy_version *version, int *num_inout)
{
	int r;
	int local_vers_num = POLICIES_TYPE_MAX;
	struct policy_version local_vers[POLICIES_TYPE_MAX];
	
	if((r = tcs_util_read_policies_version (local_vers, &local_vers_num))) {
		httc_util_pr_error ("[tcs_util_read_policies_version] r: 0x%08x\n", r);
		return r;
	}

	if((r = tcs_get_policies_version_from_tpcm (version, num_inout))) {
		httc_util_pr_error ("[tcs_get_policies_version_from_tpcm] r: 0x%08x\n", r);
		return r;
	}
	int i,j;
	version[POLICY_TYPE_FILE_INTEGRITY].be_version = local_vers[POLICY_TYPE_FILE_INTEGRITY].be_version;

	for (i = 0; i < *num_inout; i++){
		if (ntohl (version[i].be_policy) == POLICY_TYPE_CRITICAL_FILE_INTEGRITY){
			for (j = 0; j < local_vers_num; j++){
				if (ntohl (local_vers[j].be_policy) == POLICY_TYPE_CRITICAL_FILE_INTEGRITY){
					version[i].be_version = MAX (version[i].be_version, local_vers[j].be_version);
				}
			}
		}
	}
	return TSS_SUCCESS;
}
	
int tcs_get_tpcm_log (int *length, unsigned char *log){

	int ret = 0;
	uint32_t cmdLen = 0;
	int rspLen = sizeof(get_tpcmlog_rsp_st) + *length;
	get_tpcmlog_req_st *cmd = NULL;
	get_tpcmlog_rsp_st *rsp = NULL;
	
	if (NULL == (cmd = (get_tpcmlog_req_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (get_tpcmlog_rsp_st *)httc_malloc (rspLen))){
		httc_util_pr_error ("Rsp Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof(get_tpcmlog_req_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetTpcmLog);
	cmd->uimaxlength = htonl(*length);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))	goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if (0 == (ret = tpcmRspRetCode (rsp))){
		if ((int)(*length) < (int)(tpcmRspLength (rsp) - sizeof (get_tpcmlog_rsp_st))){
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		
		*length = tpcmRspLength (rsp) - sizeof (get_tpcmlog_rsp_st);
		if (*length) memcpy (log, rsp->uaLog, *length);
	}

out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	//DEBUG (ret);
	return ret;
}

