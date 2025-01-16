/**
****************************************************************************************
 * @FilePath: tcs_selftest.c
 * @Author: wll
 * @Date: 2023-06-19 09:57:22
 * @LastEditors: 
 * @LastEditTime: 2023-06-19 10:19:00
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/

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


#include "mem.h"
#include "sys.h"
#include "file.h"
#include "debug.h"
#include "convert.h"
#include "transmit.h"
#include "tpcm_command.h"
#include "tcs_config.h"
#include "tcs_attest.h"
#include "tcs_selftest.h"
#include "tcs_selftest_def.h"
#include "tcs_error.h"
#include "tutils.h"



int tcs_tpcm_selftest(uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_selftest_rsp_st *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SELFTEST);
	rsp = (tpcm_selftest_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) {
		goto out;
	}
	
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
	if(buffer) {
		httc_free(buffer);
	}
	return ret;
}
