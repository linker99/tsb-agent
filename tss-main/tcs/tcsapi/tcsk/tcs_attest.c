#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/version.h>

#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_tpcm.h"
#include "tcs_constant.h"
#include "kutils.h"

#include "debug.h"
#include "tdd.h"
#include "tddl.h"

#pragma pack(push,1)

typedef struct {
	RESPONSE_HEADER;
	uint32_t status;
}get_trusted_status_rsp_st;

typedef struct {
	RESPONSE_HEADER;
	uint32_t status;
}get_trust_status_rsp;

typedef struct{
	RESPONSE_HEADER;
	uint32_t feature;
}get_tpcm_feature_rsp;


typedef struct{
	COMMAND_HEADER;
	uint64_t host_report_time;
	uint64_t host_startup_time;
	unsigned char host_id[MAX_HOST_ID_SIZE];
	uint32_t uiHostIp;
	struct tsb_runtime_info info;
	uint64_t Nonce;
}tcs_req_generate_trust_report;

typedef struct{
	RESPONSE_HEADER;
	struct trust_report report;
}tcs_rsp_generate_trust_report;

typedef struct{
	RESPONSE_HEADER;
	uint32_t length;
	uint8_t  data[0];
}get_tpcm_id_rsp;

#pragma pack(pop)

extern uint32_t gui_trust_status;
extern uint32_t dmeasure_trust_status;
extern uint32_t intercept_trust_status;

int tpcm_ioctl_get_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	((get_trusted_status_rsp_st *)rsp)->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
	((get_trusted_status_rsp_st *)rsp)->uiRspLength = htonl(sizeof(get_trusted_status_rsp_st));
	((get_trusted_status_rsp_st *)rsp)->uiRspRet = htonl(TSS_SUCCESS);
	((get_trusted_status_rsp_st *)rsp)->status = htonl(gui_trust_status);
	*rspLen = sizeof(get_trusted_status_rsp_st);
	return 0;
}

int tpcm_ioctl_get_dmeasure_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	((get_trusted_status_rsp_st *)rsp)->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
	((get_trusted_status_rsp_st *)rsp)->uiRspLength = htonl(sizeof(get_trusted_status_rsp_st));
	((get_trusted_status_rsp_st *)rsp)->uiRspRet = htonl(TSS_SUCCESS);
	((get_trusted_status_rsp_st *)rsp)->status = htonl(dmeasure_trust_status);
	*rspLen = sizeof(get_trusted_status_rsp_st);
	return 0;
}
int tpcm_ioctl_get_intercept_trusted_status(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	((get_trusted_status_rsp_st *)rsp)->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
	((get_trusted_status_rsp_st *)rsp)->uiRspLength = htonl(sizeof(get_trusted_status_rsp_st));
	((get_trusted_status_rsp_st *)rsp)->uiRspRet = htonl(TSS_SUCCESS);
	((get_trusted_status_rsp_st *)rsp)->status = htonl(intercept_trust_status);
	*rspLen = sizeof(get_trusted_status_rsp_st);
	return 0;
}
int tpcm_ioctl_generate_trust_report(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen){

	int ret = 0;
	int cmdlen = sizeof(tcs_req_generate_trust_report);
	tcs_req_generate_trust_report *cmd = NULL;
	uint64_t startup_time = 0;
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0))
		struct timespec64 ts;
	#else
		struct timespec ts;
	#endif
	if (NULL == (cmd = (tcs_req_generate_trust_report *)tdd_alloc_data_buffer (cmdlen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy(cmd,ucmd,cmdlen);
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0))
		getboottime64(&ts);
	#else
		getboottime(&ts);
	#endif	
	startup_time = htonll(ts.tv_sec);
	tpcm_memcpy(&(cmd->host_startup_time), &startup_time, sizeof(uint64_t));	 
	ret = tcs_get_tsb_trust_info((struct tsb_runtime_info *)&(cmd->info));
#ifndef TSS_DEBUG
	if(ret) goto fail;
#endif	
	cmd->info.illegalProcessExecCount = htonl(cmd->info.illegalProcessExecCount);
	cmd->info.illegalDynamicLibLoadCount = htonl(cmd->info.illegalDynamicLibLoadCount);
	cmd->info.illegalKernelModuleLoadCount = htonl(cmd->info.illegalKernelModuleLoadCount);
	cmd->info.illegalFileAccessCount = htonl(cmd->info.illegalFileAccessCount);
	cmd->info.illegalDeviceAccessCount = htonl(cmd->info.illegalDeviceAccessCount);
	cmd->info.illegalNetworkVisitCount = htonl(cmd->info.illegalNetworkVisitCount);
	cmd->info.illegalNetworkRequestCount = htonl(cmd->info.illegalNetworkRequestCount);
	cmd->info.measureProcessCodeFailureCount = htonl(cmd->info.measureProcessCodeFailureCount);
	cmd->info.measureKcodeMeasureFailCount = htonl(cmd->info.measureKcodeMeasureFailCount);
	cmd->info.measureKdataMeasureFailCount = htonl(cmd->info.measureKdataMeasureFailCount);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdlen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTrustedCredential);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdlen, rsp, (int *)rspLen);
	goto out;
#ifndef TSS_DEBUG	
fail:
	*rspLen = sizeof(tpcm_rsp_header_st);
	((tpcm_rsp_header_st *)rsp)->uiRspLength = htonl(*rspLen);
	((tpcm_rsp_header_st *)rsp)->uiRspRet = htonl(TSS_ERR_PARAMETER);
	((tpcm_rsp_header_st *)rsp)->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
#endif
out:
	if(cmd) tdd_free_data_buffer (cmd);
	return ret;
}

int tpcm_get_trust_status(uint32_t *status)
{
	int ret = 0;
	int cmdLen = sizeof (tpcm_req_header_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_trust_status_rsp *rsp = NULL;

	if((buffer = (uint8_t *)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_req_header_st *)buffer;
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTrustedStatus);
	rsp = (get_trust_status_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}
	
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_trust_status_rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
	}
	
out:	
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}
	
	return ret;
}

extern uint32_t gui_trust_status;

int tcsk_get_trust_status(uint32_t *status)
{
	*status = gui_trust_status;
	
	return 0;
}
EXPORT_SYMBOL_GPL(tcsk_get_trust_status);

int tcsk_get_tpcm_features(uint32_t *features)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_tpcm_feature_rsp *rsp = NULL;

	if((buffer = (uint8_t *)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetTpcmFeature);
	rsp = (get_tpcm_feature_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_tpcm_feature_rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*features = htonl(rsp->feature);
	}

out:
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}
	
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_get_tpcm_features);

static int tcsk_get_tpcm_id(unsigned char *id,int *len_inout)
{
	int ret = 0;
	tpcm_req_header_st *cmd = NULL;
	get_tpcm_id_rsp *rsp = NULL;
	int cmdLen = sizeof(tpcm_req_header_st);
	uint8_t *buffer = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	
	if(NULL == (buffer = (uint8_t *)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE))){
  		httc_util_pr_error("[%s : %d] kmalloc buffer hter\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buffer;
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetMark);
	rsp = (get_tpcm_id_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);
	
	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != (sizeof (get_tpcm_id_rsp) + ntohl(rsp->length))) {
			httc_util_pr_error("Invalid response length (%d != %d)\n",
				tpcmRspLength(rsp), (int)(sizeof (get_tpcm_id_rsp) + ntohl(rsp->length)));
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		if((int)(*len_inout) < (int)ntohl(rsp->length)) {
			httc_util_pr_error("out space is not enough (%d < %d)\n", *len_inout, ntohl(rsp->length));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*len_inout = ntohl (rsp->length);
		memcpy (id, rsp->data, *len_inout);
	}

out :
	if (buffer)
		tdd_free_data_buffer (buffer);

	return ret;
}

static unsigned char tpcm_local_id[MAX_TPCM_ID_SIZE] = {0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												     0xff, 0xff, 0xff, 0xff,
												    };
int tcs_util_set_tpcm_id(void)
{	
	int ret = 0;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE] = {0};
	int tpcm_id_len = MAX_TPCM_ID_SIZE;
	 
	if(0 == (ret = tcsk_get_tpcm_id(tpcm_id,  &tpcm_id_len))){
		memcpy(tpcm_local_id, tpcm_id, tpcm_id_len);
		httc_util_dump_hex("tcs_set_tpcm_id : ",  tpcm_local_id,  tpcm_id_len);
	}

	return ret;
}

int tcs_ioctl_get_tpcm_id(uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	unsigned char tpcm_local_arr[MAX_TPCM_ID_SIZE] = {0};
	tpcm_req_header_st  *cmd = NULL;
	tpcm_req_header_st  *tpcm_cmd = (tpcm_req_header_st *)ucmd;
	get_tpcm_id_rsp  *rsp_data = (get_tpcm_id_rsp  *)rsp;
	uint8_t *buffer = NULL;

	memset(tpcm_local_arr, 0xff, MAX_TPCM_ID_SIZE);
	if(memcmp(tpcm_local_id , tpcm_local_arr, MAX_TPCM_ID_SIZE)){ 
		rsp_data->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
		rsp_data->uiRspLength = htonl(sizeof(get_tpcm_id_rsp) + MAX_TPCM_ID_SIZE);
		rsp_data->uiRspRet = 0;
		rsp_data->length = htonl(MAX_TPCM_ID_SIZE);
		memcpy(rsp_data->data, tpcm_local_id, MAX_TPCM_ID_SIZE);
		*rspLen = sizeof(get_tpcm_id_rsp) + MAX_TPCM_ID_SIZE;
		return ret;
	}  
	if (NULL == (buffer = (uint8_t *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error("[%s:%d] tpcm_ioctl_get_tpcm_id alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buffer;
	cmd->uiCmdTag  = tpcm_cmd->uiCmdTag;
	cmd->uiCmdLength = tpcm_cmd->uiCmdLength;
	cmd->uiCmdCode = tpcm_cmd->uiCmdCode;

	ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen);

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != (sizeof (get_tpcm_id_rsp) + ntohl(((get_tpcm_id_rsp*)rsp)->length))) {
			httc_util_pr_error("Invalid response length (%d != %d)\n",
				tpcmRspLength(rsp), (int)(sizeof (get_tpcm_id_rsp) + ntohl(((get_tpcm_id_rsp*)rsp)->length)));
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		if(MAX_TPCM_ID_SIZE != ntohl(((get_tpcm_id_rsp*)rsp)->length)) {
			httc_util_pr_error("Invalid tpcmid (%d != %d)\n", MAX_TPCM_ID_SIZE, ntohl(((get_tpcm_id_rsp*)rsp)->length));
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy(tpcm_local_id, ((get_tpcm_id_rsp *)rsp)->data, ntohl(((get_tpcm_id_rsp *)rsp)->length));
	}
	
out:
	if (buffer) tdd_free_data_buffer (buffer); 
	return ret;
}

