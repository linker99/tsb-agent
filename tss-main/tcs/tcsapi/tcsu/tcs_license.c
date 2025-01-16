#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "mem.h"
#include "sys.h"
#include "debug.h"
#include "uutils.h"
#include "convert.h"
#include "tcs_error.h"
//#include "tcs_tpcm_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "transmit.h"
#include "tcs_constant.h"
#include "tcs_license.h"
#ifndef NO_TSB
#include "tsbapi/tsb_admin.h"
#endif

#pragma pack(push, 1)
typedef struct{
	COMMAND_HEADER;
	struct license_param licreq;
}get_license_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t ualic[0];
}get_license_rsp_st;


typedef struct{
	COMMAND_HEADER;
	uint8_t lic[0];
}tpcm_import_license_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t status;
	uint32_t left;
}tpcm_license_status_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t status;
	uint64_t deadline;
}tpcm_license_info_st;

typedef struct{
	COMMAND_HEADER;
	uint64_t udTime;
}reset_req_st;

typedef struct{
	COMMAND_HEADER;
//	uint32_t attr;
}license_info_req_st;

typedef struct get_license_entity_rsp{
	RESPONSE_HEADER;
	uint32_t num;
	license_entity_st data[0];
}get_license_entity_rsp_st;

#pragma pack(pop)

int tcs_generate_license_request(struct license_req *req, const struct license_param *param)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	get_license_req_st *cmd = NULL;
	get_license_rsp_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (get_license_req_st *)buffer;
	cmdLen = sizeof(get_license_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_LicenseRequest);
	cmd->licreq.license_type = htonl(param->license_type);
	cmd->licreq.shelf_life = htonl (param->shelf_life);
	cmd->licreq.client_id_length = htonl(param->client_id_length);
	cmd->licreq.host_id_length = htonl(param->host_id_length);
	memcpy(cmd->licreq.client_id, param->client_id, MAX_CLIENT_ID_SIZE);
	memcpy(cmd->licreq.host_id, param->host_id, MAX_HOST_ID_SIZE);
	rsp = (get_license_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if ((tpcmRspLength(rsp) - sizeof(tpcm_rsp_header_st)) != (sizeof (struct license_req) + DEFAULT_SIGNATURE_SIZE)){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy(req, rsp->ualic, sizeof (struct license_req) + DEFAULT_SIGNATURE_SIZE);
	}

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_import_license(struct license *license)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	
	uint8_t *buffer = NULL;
	tpcm_import_license_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if((buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_import_license_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof(tpcm_import_license_st) + sizeof(struct license) + DEFAULT_SIGNATURE_SIZE;
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_ImportLicense);
	
	memcpy(cmd->lic, license, sizeof(struct license) + DEFAULT_SIGNATURE_SIZE);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if((ret = tpcmRspRetCode(rsp)) != 0) {
		goto out;
	}
	
	if(tpcmRspLength(rsp) != sizeof(tpcm_rsp_header_st)) {
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_get_license_status(int *status, int *left)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	license_info_req_st *cmd = NULL;
	tpcm_license_status_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (license_info_req_st *)buffer;
	rsp = (tpcm_license_status_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof(license_info_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetAuthorizationStatus);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(sizeof(tpcm_license_status_st) != tpcmRspLength(rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}

		*status = ntohl(rsp->status);
		*left = ntohl(rsp->left);
	}

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_get_license_info(int *status, uint64_t *deadline)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	license_info_req_st *cmd = NULL;
	tpcm_license_info_st *rsp = NULL;

	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (license_info_req_st *)buffer;
	rsp = (tpcm_license_info_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof(license_info_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetLicenseInfo);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(sizeof(tpcm_license_info_st) != tpcmRspLength(rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
		*deadline = ntohll(rsp->deadline);
	}

out:
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

int tcs_get_license_entity (struct license_entity *data, int *num)
{
	int ret = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	license_info_req_st *cmd = NULL;
	get_license_entity_rsp_st *rsp = NULL;

	if(data == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if (NULL == (cmd = (license_info_req_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (get_license_entity_rsp_st*)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE/2);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (sizeof (license_info_req_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_GetLicenseEntity);

	if (0 != (ret = tpcm_transmit (cmd, sizeof (license_info_req_st), rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (sizeof (get_license_entity_rsp_st) > tpcmRspLength (rsp)){
			httc_util_pr_error ("Response steam error.\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*num = ntohl (rsp->num);
		memcpy(data,rsp->data,(*num) * sizeof(license_entity_st));
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;
}


#define HTTC_TSS_CONFIG_PATH_BAK	"/usr/local/httcsec/conf.bak/"

int tcs_reset_test_license()
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	reset_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	struct timeval tv;
	struct timezone tz;
	char *home = NULL;
	char priv_key_path[512] = {0};

	/** 备份本地数据 */
	if (httc_util_rm (HTTC_TSS_CONFIG_PATH_BAK)){
			httc_util_pr_error ("httc_util_rm %s error\n", HTTC_TSS_CONFIG_PATH_BAK);
			ret = TSS_ERR_FILE;
			goto out;
	}
	if (!access (HTTC_TSS_CONFIG_PATH, F_OK) && rename (HTTC_TSS_CONFIG_PATH, HTTC_TSS_CONFIG_PATH_BAK)){
			httc_util_pr_error ("backup %s error\n", HTTC_TSS_CONFIG_PATH);
			ret = TSS_ERR_FILE;
			goto out;
	}
	if (mkdir (HTTC_TSS_CONFIG_PATH, 0777)){
		httc_util_pr_error ("httc_util_mkdir %s error\n", HTTC_TSS_CONFIG_PATH);
		ret = TSS_ERR_FILE;
		goto out;
	}
	
	if((ret = gettimeofday(&tv, &tz)) != 0) {
		httc_util_pr_error ("Get time failed!\n");
		goto conf;
	}
	
	if((buffer = httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		ret = TSS_ERR_NOMEM;
		goto conf;
	}
	
	cmd = (reset_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof(reset_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_Reset);
	cmd->udTime = htonll(tv.tv_sec);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto conf;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto conf;
	}
	
	ret = tpcmRspRetCode(rsp);

conf:
	if (!ret){
		/** 清除本地数据 */
		if (httc_util_rm (HTTC_TSS_CONFIG_PATH_BAK)){
				httc_util_pr_error ("httc_util_rm %s error\n", HTTC_TSS_CONFIG_PATH_BAK);
				ret = TSS_ERR_FILE;
				goto out;
		}
	
		home = getenv("HOME");
		//httc_util_pr_dev ("$HOME: %s\n", home);
		if ((snprintf(priv_key_path, sizeof (priv_key_path), "%s/%s", home,HTTC_TSS_PRIV_PREFIX) <= 0)
			|| (httc_util_rm (priv_key_path))){
			httc_util_pr_error ("httc_util_rm %s error\n", priv_key_path);
			ret = TSS_ERR_FILE;
			goto out;
		}
	}else{
		/** 恢复本地数据 */
		if (httc_util_rm (HTTC_TSS_CONFIG_PATH)){
				httc_util_pr_error ("httc_util_rm %s error\n", HTTC_TSS_CONFIG_PATH);
				ret = TSS_ERR_FILE;
				goto out;
		}
		if (!access (HTTC_TSS_CONFIG_PATH_BAK, F_OK) && rename (HTTC_TSS_CONFIG_PATH_BAK, HTTC_TSS_CONFIG_PATH)){
			httc_util_pr_error ("restore %s error\n", HTTC_TSS_CONFIG_PATH);
			ret = TSS_ERR_FILE;
			goto out;
		} 
	}

out:
	if(buffer) {
		httc_free(buffer);
	}

	return ret;
}


int tcs_reset_tpcm(void)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	reset_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	struct timeval tv;
	struct timezone tz;
	
	if((ret = gettimeofday(&tv, &tz)) != 0) {
		httc_util_pr_error ("Get time failed!\n");
		return ret;
	}
	
	if((buffer = httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (reset_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof(reset_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_Reset_TPCM);
	cmd->udTime = htonll(tv.tv_sec);
	
	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
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


