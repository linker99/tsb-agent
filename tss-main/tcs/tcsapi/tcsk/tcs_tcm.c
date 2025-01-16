#include <linux/kernel.h>
#include <linux/slab.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_config.h"
#include "tcs_error.h"
#include "tdd.h"
#include "tddl.h"

#define TCM_TAG_REQ_COMMAND	0x00C1 	/** A command with no authentication.  */
#define TCM_TAG_RSP_COMMAND	0x00C4 	/** A response from a command with no authentication */

#define TCM_ORD_Init 			0x00008097
#define TCM_ORD_Startup			0x00008099

#define TCM_RSP_HEADER_LEN 10
#define TCM_COMMNAD_HEADER	\
	uint16_t cmd_type;\
	uint32_t total_length;\
	uint32_t ordinal_no;
#define TCM_RESPONSE_HEADER	\
	uint16_t tag; \
	uint32_t returnSize;\
	uint32_t returnCode;
extern volatile uint32_t recv_mdelay;
	
#pragma pack(push, 1)

typedef struct{
	TCM_COMMNAD_HEADER;
}tcm_req_header_st;

typedef struct{
	TCM_RESPONSE_HEADER;
}tcm_rsp_header_st;

typedef struct {
	TCM_COMMNAD_HEADER;
	uint16_t mode;
}tcm_startup_st;

#pragma pack(pop)

static uint32_t tcmRspRetCode (void *rsp){
	uint32_t rc_n = 0;
	tpcm_memcpy (&rc_n, &((tcm_rsp_header_st *)rsp)->returnCode, sizeof (rc_n));
	return ntohl (rc_n);
}

static uint16_t tcmRspTag (void *rsp){
	uint16_t tag_n = 0;
	tpcm_memcpy (&tag_n, &((tcm_rsp_header_st *)rsp)->tag, sizeof (tag_n));
	return ntohs (tag_n);
}

int tcm_init (void)
{
	int ret = 0;
	uint32_t cmdLen = sizeof(tcm_req_header_st);
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tcm_req_header_st *cmd = NULL;
	tcm_rsp_header_st *rsp = NULL;
	uint32_t cmdLen_n = htonl (cmdLen);
	uint32_t ordinal_no_n = htonl (TCM_ORD_Init);
	uint16_t tag = 0;

	if (NULL == (cmd = (tcm_req_header_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tcm_rsp_header_st *)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->cmd_type = htons (TCM_TAG_REQ_COMMAND);
	tpcm_memcpy (&cmd->total_length, &cmdLen_n, 4);
	tpcm_memcpy (&cmd->ordinal_no, &ordinal_no_n, 4);

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	recv_mdelay = 1000;
//#endif

	if (0 != (ret = tcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)))		goto out;

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	recv_mdelay = 500;
//#endif

	if ((tag = tcmRspTag (rsp)) != TCM_TAG_RSP_COMMAND){
		httc_util_pr_error ("Invalid tcm rsp tag(0x%02X)\n", tag);
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	ret = tcmRspRetCode (rsp);
out:
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;
}

int tcm_startup (uint16_t mode)
{
	int ret = 0;
	uint32_t cmdLen = sizeof(tcm_startup_st);
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tcm_startup_st *cmd = NULL;
	tcm_rsp_header_st *rsp = NULL;
	uint16_t mode_n = htons (mode);
	uint32_t cmdLen_n = htonl (cmdLen);
	uint32_t ordinal_no_n = htonl (TCM_ORD_Startup);
	uint16_t tag = 0;

	if (NULL == (cmd = (tcm_startup_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tcm_rsp_header_st *)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->cmd_type = htons (TCM_TAG_REQ_COMMAND);
	tpcm_memcpy (&cmd->total_length, &cmdLen_n, 4);
	tpcm_memcpy (&cmd->ordinal_no, &ordinal_no_n, 4);
	tpcm_memcpy (&cmd->mode, &mode_n, 2);

	if (0 != (ret = tcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)))		goto out;
	
	if ((tag = tcmRspTag (rsp)) != TCM_TAG_RSP_COMMAND){
		httc_util_pr_error ("Invalid tcm rsp tag(0x%02X)\n", tag);
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	ret = tcmRspRetCode (rsp);
out:
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;
}

