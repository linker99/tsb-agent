/**
****************************************************************************************
 * @FilePath: tcs_selftest.c
 * @Author: wll
 * @Date: 2023-06-26 14:10:43
 * @LastEditors: 
 * @LastEditTime: 2023-06-26 14:12:10
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/


#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_tpcm.h"
#include "tcsk_selftest.h"

#pragma pack(push, 1)

typedef struct {
	RESPONSE_HEADER;
	uint32_t status;
}tpcm_selftest_rsp_st;

#pragma pack(pop)

int tcsk_tpcm_selftest(uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_selftest_rsp_st *rsp = NULL;
	
	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SELFTEST);
	rsp = (tpcm_selftest_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	rsp->status = 0;
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if((int)(tpcmRspLength(rsp) - sizeof (tpcm_selftest_rsp_st)) != 0) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
	}
	*status = ntohl(rsp->status);
out:
	if (buffer)	tdd_free_data_buffer (buffer);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_tpcm_selftest);
