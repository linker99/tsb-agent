#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include "mem.h"
#include "sem.h"
#include "debug.h"
#include "convert.h"
#include "transmit.h"
#include "tcs_error.h"
#include "tpcm_command.h"
#include "tcs_config.h"
#include "tcs_tpcm.h"
#include "tcs.h"
#include "tcs_constant.h"
#include "tcs_attest.h"


#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
	uint32_t value;
}set_tpcm_switch_st;

typedef struct{
	COMMAND_HEADER;
	unsigned char tpcm_id[MAX_TPCM_ID_SIZE];
}get_tpcm_switch_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t value;
}get_tpcm_switch_rsp_st;

#pragma pack(pop)

int tcs_set_tpcm_switch(uint32_t value){
	int ret = 0;
	int cmdLen = 0;
	int id_len = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	set_tpcm_switch_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (set_tpcm_switch_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (set_tpcm_switch_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetSwitch);
	id_len = sizeof(cmd->tpcm_id);
	int rc = tcs_get_tpcm_id(cmd->tpcm_id, &id_len);
	if (rc)
	{
		httc_util_pr_error("[tcs_get_tpcm_id] ret: 0x%08x\n", rc);
		rc=TSS_ERR_BAD_DATA;
		goto out;
	}
	cmd->value = htonl(value);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);
out:	
	if (buffer) httc_free (buffer);
	return ret;	
}

int tcs_get_tpcm_switch (uint32_t *value)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	get_tpcm_switch_st *cmd = NULL;
	get_tpcm_switch_rsp_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (get_tpcm_switch_st *)buffer;
	rsp = (get_tpcm_switch_rsp_st *)((uint8_t *)buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof (get_tpcm_switch_st);	
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetSwitch);

	int id_len = sizeof(cmd->tpcm_id);
	int rc = tcs_get_tpcm_id(cmd->tpcm_id, &id_len);
        if (rc)
        {
                httc_util_pr_error("[tcs_get_tpcm_id] ret: 0x%08x\n", rc);
                rc=TSS_ERR_BAD_DATA;
                goto out;
        }

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	
	if(0 == (ret = tpcmRspRetCode (rsp))){
		*value = htonl(rsp->value);
	}

out:
	if (buffer) httc_free (buffer);
	return ret;
}

