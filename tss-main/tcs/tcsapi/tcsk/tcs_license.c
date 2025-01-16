#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_kernel.h"
#include "tcs_policy_mgmt.h"
#include "tcs_license.h"

#pragma pack(push, 1)

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
//	uint32_t attr;
}license_info_req_st;

typedef struct get_license_entity_rsp{
	RESPONSE_HEADER;
	uint32_t num;
	license_entity_st data[0];
}get_license_entity_rsp_st;

#pragma pack(pop)

int tcs_ioctl_reset_license (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	uint8_t *cmd = NULL;

	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	tpcm_memcpy (cmd, ucmd, ucmdLen);	
	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);
	if (!ret && (0 == (tpcmRspRetCode(rsp)))){
		if ((ret = tcs_policy_management_reload ())){
			httc_util_pr_error ("tcs_policy_management_reload hter: %d(0x%x)\n", ret, ret);
		}
		if ((ret = tcs_util_set_tpcm_id ())){
			httc_util_pr_error("tcs_util_set_tpcm_id hter : %d\n", ret);	
		}
	}

	if(cmd) tdd_free_data_buffer(cmd);
	return ret;
}

int tcsk_get_license_status(int *status, int *left)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	license_info_req_st *cmd = NULL;
	tpcm_license_status_st *rsp = NULL;

	if((buffer = tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (license_info_req_st *)buffer;
	rsp = (tpcm_license_status_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof(license_info_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetAuthorizationStatus);

	if((ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
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
		tdd_free_data_buffer(buffer);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_get_license_status);

int tcsk_get_license_info (int *status, uint64_t *deadline)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	uint64_t trans = 0;
	license_info_req_st *cmd = NULL;
	tpcm_license_info_st *rsp = NULL;

	if((buffer = tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (license_info_req_st *)buffer;
	rsp = (tpcm_license_info_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof(license_info_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetLicenseInfo);

	if((ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
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
		trans = ntohll(rsp->deadline);
		tpcm_memcpy(deadline, &trans, sizeof(uint64_t));
	}

out:
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}

	return ret;
}

EXPORT_SYMBOL_GPL (tcsk_get_license_info);

int tcsk_get_license_entity (struct license_entity *data, int *num)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	license_info_req_st *cmd = NULL;
	get_license_entity_rsp_st *rsp = NULL;

	if(data == NULL || num == NULL) return TSS_ERR_PARAMETER;

	if((buffer = tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (license_info_req_st *)buffer;
	rsp = (get_license_entity_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof(license_info_req_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetLicenseEntity);

	if((ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if (sizeof (get_license_entity_rsp_st) > tpcmRspLength (rsp)){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}

		*num = ntohl (rsp->num);
		memcpy(data,rsp->data,(*num) * sizeof(license_entity_st));
	}

out:
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}

	return ret;
}

EXPORT_SYMBOL_GPL (tcsk_get_license_entity);

