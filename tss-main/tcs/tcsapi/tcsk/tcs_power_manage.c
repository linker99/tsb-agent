#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>

#include "tdd.h"
#include "tddl.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tcs_tpcm.h"
#include "version.h"
#include "memdebug.h"
#include "debug.h"

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;	
	uint32_t uiPmType;
}pm_manage_req_st;

#pragma pack(pop)

int tcsk_power_manage(uint32_t pmtype, uint32_t *tpcmRes)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	pm_manage_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
		
	if (NULL == (buffer = tdd_alloc_data_buffer_api(CMD_DEFAULT_ALLOC_SIZE)))
	{
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (pm_manage_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	cmdLen = sizeof(pm_manage_req_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_PowerManage);
	cmd->uiPmType = htonl(pmtype);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);
	
out:	
	if (buffer)	tdd_free_data_buffer (buffer);
	//DEBUG (ret);
	return ret;
}

int tpcm_pm_suspend(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	

	ret = tcsk_power_manage(S3_OFF,&tpcmRes);
	if(ret || (tpcmRes && (tpcmRes != TPCM_INVALID_COMMAND)))	return -1;
	return 0;
}

int tpcm_pm_resume(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval now;
	

	httc_gettimeofday (&now);
	ret = tcsk_set_system_time (now.tv_sec, &tpcmRes);
	if (ret || tpcmRes){
		httc_util_pr_error ("SetSystemTime hter: ret(0x%08x),tpcmRes(0x%08x)\n", ret, tpcmRes);
	}
	return 0;
}

int tpcm_pm_freeze(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	

	ret = tcsk_power_manage(S4_OFF,&tpcmRes);
	if(ret || (tpcmRes && (tpcmRes != TPCM_INVALID_COMMAND)))	return -1;
	return 0;
}

int tpcm_pm_restore(void)
{
	int ret = 0;
	uint32_t tpcmRes = 0;
	struct timeval now;
	

	httc_gettimeofday (&now);
	ret = tcsk_set_system_time (now.tv_sec, &tpcmRes);
	if (ret || tpcmRes){
		httc_util_pr_error ("SetSystemTime hter: ret(0x%08x),tpcmRes(0x%08x)\n", ret, tpcmRes);
	}
	return 0;
}

int tpcm_pm_callbacks_register (void)
{	
	int ret = -1;

	ret = tpcm_pm_callback_register(tpcm_pm_suspend,S3_OFF);
	if (ret){
		httc_util_pr_error ("tpcm_pm_callback_register %d hter!\n", S3_OFF);
		return -1;
	}	
	ret = tpcm_pm_callback_register(tpcm_pm_resume,S3_ON);
	if (ret){
		httc_util_pr_error ("tpcm_pm_callback_register %d hter!\n", S3_ON);
		tpcm_pm_callback_unregister(tpcm_pm_suspend,S3_OFF);
		return -1;
	}
	ret = tpcm_pm_callback_register(tpcm_pm_freeze,S4_OFF);
	if (ret){
		httc_util_pr_error ("tpcm_pm_callback_register %d hter!\n", S4_OFF);
		tpcm_pm_callback_unregister(tpcm_pm_suspend,S3_OFF);
		tpcm_pm_callback_unregister(tpcm_pm_resume,S3_ON);
		return -1;
	}
	ret = tpcm_pm_callback_register(tpcm_pm_restore,S4_ON);
	if (ret){
		httc_util_pr_error ("tpcm_pm_callback_register %d hter!\n", S4_ON);
		tpcm_pm_callback_unregister(tpcm_pm_suspend,S3_OFF);
		tpcm_pm_callback_unregister(tpcm_pm_resume,S3_ON);
		tpcm_pm_callback_unregister(tpcm_pm_freeze,S4_OFF);
		return -1;
	}
	return 0;
}

void tpcm_pm_callbacks_unregister (void)
{
	tpcm_pm_callback_unregister(tpcm_pm_suspend,S3_OFF);
	tpcm_pm_callback_unregister(tpcm_pm_resume,S3_ON);
	tpcm_pm_callback_unregister(tpcm_pm_freeze,S4_OFF);
	tpcm_pm_callback_unregister(tpcm_pm_restore,S4_ON);
}

