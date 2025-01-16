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

#define SEM_KEY_TCS			0x9998

static int sem_id = -1;

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	uint64_t udTime;
}set_system_time_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t length;
	uint8_t version[0];
}get_tpcm_version_rsp_st;

#pragma pack(pop)

int tcs_set_system_time(uint64_t nowtime, uint32_t *tpcmRes){
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	set_system_time_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (set_system_time_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (set_system_time_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetSystemTime);
	cmd->udTime = htonll (nowtime);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);
out:	
	if (buffer) httc_free (buffer);
	return ret;	
}

int tcs_get_version (uint32_t * size, uint8_t * version, uint32_t * tpcmRes)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_tpcm_version_rsp_st *rsp = NULL;

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_req_header_st *)buffer;
	rsp = (get_tpcm_version_rsp_st *)((uint8_t *)buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	
	cmdLen = sizeof (tpcm_req_header_st);	
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetVersion);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	
	if(0 == (*tpcmRes = tpcmRspRetCode (rsp))){
		if (ntohl(rsp->length) != (tpcmRspLength(rsp) - sizeof(get_tpcm_version_rsp_st))){
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		
		if( *size < ntohl(rsp->length)){
			ret = TSS_ERR_OUTPUT_EXCEED;
			httc_util_pr_error ("Out space is not enought!\n");
			goto out;
		}
		
		*size = ntohl(rsp->length);
		memcpy(version,rsp->version,*size);
	}

out:
	if (buffer) httc_free (buffer);
	return ret;
}

int tcs_util_sem_val (int index)
{
	return httc_util_sem_val (sem_id, index);
}
int tcs_util_sem_get (int index)
{
	int r = -1;
	if ((r = httc_util_sem_p (sem_id, index))){
		httc_util_pr_error ("httc_util_sem_p[%d] error: %d\n", index, r);
		return (r == EAGAIN) ? TSS_ERR_SEM_TIMEOUT : TSS_ERR_SEM;
	}
	return TSS_SUCCESS;
}
void tcs_util_sem_release (int index)
{
	httc_util_sem_v (sem_id, index);
}

int __tcs_init(void) __attribute__((constructor));
void __tcs_deinit(void) __attribute__((destructor));

int __tcs_init(void)
{
	sem_id = httc_util_semget_single (SEM_KEY_TCS, TCS_SEM_INDEX_MAX);
	if (sem_id < 0){
		httc_util_pr_error ("httc_util_semget_single error: %d\n", sem_id);
		return -1;
	}
	return 0;
}

void __tcs_deinit(void)
{
	return ;
}

