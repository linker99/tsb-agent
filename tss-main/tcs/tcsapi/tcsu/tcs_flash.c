#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "transmit.h"

#define FLASH_WR_SIZE 		0x10000

#pragma pack (push, 1)

typedef struct{
	COMMAND_HEADER;
	uint32_t uiZoon;
	uint32_t uiOffset;
	uint32_t uiSize;
}flash_read_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t uaData[0];
}flash_read_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiZoon;
	uint32_t uiOffset;
	uint32_t uiSize;
	uint8_t uaData[0];
}flash_write_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiZoon;
	uint32_t uiOffset;
	uint32_t uiSize;
}flash_erase_req_st;

#pragma pack (pop)

int tcs_flash_read (uint32_t zoon, uint32_t offset, uint32_t size, uint8_t *data, uint32_t *tpcmRes)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	flash_read_req_st *cmd = NULL;
	flash_read_rsp_st *rsp = NULL;

	if ((int)size > (int)(FLASH_WR_SIZE - sizeof (flash_read_rsp_st))){
		httc_util_pr_error ("Size is too large (%d > %d)\n",
				size, (int)(FLASH_WR_SIZE - sizeof (flash_read_rsp_st)));
		return TSS_ERR_INPUT_EXCEED;
	}
	
	if (NULL == (buffer = httc_malloc (FLASH_WR_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (flash_read_req_st *)buffer;
	rsp = (flash_read_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (flash_read_req_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_FlashRead);
	cmd->uiZoon = htonl (zoon);
	cmd->uiOffset = htonl (offset);
	cmd->uiSize = htonl (size);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	if (0 == (*tpcmRes = tpcmRspRetCode (rsp))){
		if ((int)size < (int)(tpcmRspLength (rsp) - sizeof (flash_read_rsp_st))){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		memcpy (data, rsp->uaData, size);
	}

out:	
	if (buffer)	httc_free (buffer);
	return ret;
}

int tcs_flash_write (uint32_t zoon, uint32_t offset, uint32_t size, uint8_t *data, uint32_t *tpcmRes)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	flash_write_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if ((int)size > (int)(FLASH_WR_SIZE - sizeof (flash_write_req_st))){
		httc_util_pr_error ("Size is too large (%d > %d)\n",
				size, (int)(FLASH_WR_SIZE - sizeof (flash_write_req_st)));
		return TSS_ERR_INPUT_EXCEED;
	}
	
	if (NULL == (buffer = httc_malloc (FLASH_WR_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (flash_write_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (flash_write_req_st) + size;
	if ((int)cmdLen > (int)FLASH_WR_SIZE){
		httc_free (buffer);
		httc_util_pr_error ("data is too large!\n");
		return TSS_ERR_INPUT_EXCEED;
	}
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_FlashWrite);
	cmd->uiZoon = htonl (zoon);
	cmd->uiOffset = htonl (offset);
	cmd->uiSize = htonl (size);
	memcpy (cmd->uaData, data, size);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);

out:	
	if (buffer)	httc_free (buffer);
	return ret;
}

int tcs_flash_erase (uint32_t zoon, uint32_t offset, uint32_t size, uint32_t *tpcmRes)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	flash_erase_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (flash_erase_req_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (flash_erase_req_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_FlashErase);
	cmd->uiZoon = htonl (zoon);
	cmd->uiOffset = htonl (offset);
	cmd->uiSize = htonl (size);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);

out:	
	if (buffer)	httc_free (buffer);
	return ret;
}

