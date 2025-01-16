#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_kernel.h"
#include "tcs_dmeasure.h"
#include "tcs_policy_mgmt.h"
#include "version.h"
#pragma pack (push, 1)

typedef struct get_dm_policy_rsp{
	RESPONSE_HEADER;
	int num;
	uint8_t policy[0];
}get_dm_policy_rsp_st; 

typedef struct get_dm_process_policy_rsp{
	RESPONSE_HEADER;
	int num;
    int length;
	uint8_t policy[0];
}get_dm_process_policy_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiOperation;
	uint32_t uiCtxNumber;	/** Context Number */
	struct collection_context ctx[0];
}collect_measure_req_st; 

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiMrLen;		/** Measure result length */
	uint8_t  uaMresult[0];	/** Measure result */
}collect_measure_rsp_st;

#pragma pack (pop)

int tcs_ioctl_update_dynamic_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int length = 0;
	int item_count = 0;
	struct dmeasure_policy_item *item = NULL;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	if (0 == (ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen))){
		if (0 == (ret = tcs_get_dmeasure_policy (&item, &item_count, &length))){
			ret = tcs_util_set_dmeasure_policy (item, item_count,  length);
		}
	}
	if (cmd)	tdd_free_data_buffer (cmd);
	if (item)	httc_vfree (item);
	return ret;
}

int tcs_ioctl_update_dynamic_process_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int length = 0;
	int item_count = 0;
	struct dmeasure_process_item *item = NULL;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	if (0 == (ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, rspLen))){
		if (0 == (ret = tcs_get_dmeasure_process_policy (&item, &item_count, &length))){
			ret = tcs_util_set_dmeasure_process_policy (item, item_count, length);
		}
	}
	if (cmd)	tdd_free_data_buffer (cmd);
	if (item)	httc_vfree (item);
	return ret;
}

int tcs_get_dmeasure_policy (struct dmeasure_policy_item **policy, int *item_count, int *length)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_RESPONSE_BUFFER_SIZE;
	tpcm_req_header_st *cmd = NULL;
	struct get_dm_policy_rsp *rsp = NULL;
	int policy_size = 0;

	if (NULL == (cmd = (tpcm_req_header_st *)tdd_alloc_data_buffer (TPCM_COMMAND_BUFFER_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (struct get_dm_policy_rsp *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetDmeasurePolicy);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if ((policy_size = tpcmRspLength (rsp) - sizeof (struct get_dm_policy_rsp)) < 0){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	*item_count = ntohl (rsp->num);
	if (policy_size != sizeof (struct dmeasure_policy_item) * (*item_count)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if (policy_size){
		if (NULL == (*policy = (struct dmeasure_policy_item *)httc_vmalloc (policy_size))){
			httc_util_pr_error ("mem alloc for dmeasure_policy_item hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*policy, rsp->policy, policy_size);
	}
	*length = policy_size;

out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	return ret;
}
int tcs_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length)//proc 导出
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_RESPONSE_BUFFER_SIZE;
	tpcm_req_header_st *cmd = NULL;
    get_dm_process_policy_rsp_st *rsp = NULL; 

	if (NULL == (cmd = (tpcm_req_header_st *)tdd_alloc_data_buffer (TPCM_COMMAND_BUFFER_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (struct get_dm_process_policy_rsp *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetDmeasureProcessPolicy);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if (tpcmRspLength (rsp) < sizeof (struct get_dm_process_policy_rsp)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	*item_count = ntohl (rsp->num);
	*length = ntohl (rsp->length);
	
	if (*length != (tpcmRspLength (rsp) - sizeof (struct get_dm_process_policy_rsp))){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if (*length){
		if (NULL == (*policy = (struct dmeasure_process_item *)httc_vmalloc (*length))){
			httc_util_pr_error ("mem alloc for dmeasure_policy_item hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*policy, rsp->policy, *length);
	}

out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	return ret;
}

int tcsk_collection_and_measure (uint32_t operation, uint32_t ctxNum, 
   	struct collection_context *ctx, uint32_t *tpcmRes, uint32_t *mrLen, unsigned char *mResult)
{
	int i = 0;
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	uint64_t trans = 0;
	collect_measure_req_st *cmd = NULL;
	collect_measure_rsp_st *rsp = NULL;

	if (NULL == (cmd = (collect_measure_req_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
			httc_util_pr_error ("Req Alloc hter!\n");
			return TSS_ERR_NOMEM;
	}
	
	if (NULL == (rsp = (collect_measure_rsp_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (collect_measure_req_st) + sizeof (struct collection_context) * ctxNum;
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		httc_util_pr_error ("ctx is too large!\n");
		tdd_free_data_buffer (cmd);
		tdd_free_data_buffer (rsp);
		return TSS_ERR_INPUT_EXCEED;
	}
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_CollectAndMeasure);
	cmd->uiOperation = htonl (operation);
	cmd->uiCtxNumber = htonl (ctxNum);

	for (i = 0; i < ctxNum; i++){
		if (ctx[i].name_length > MAX_DMEASURE_NAME_SIZE){
			httc_util_pr_error ("ctx[%d].name is too long (%d > %d)\n", i, ctx[i].name_length, MAX_DMEASURE_NAME_SIZE);
			ret = TSS_ERR_INPUT_EXCEED;
			goto out;
		}
		cmd->ctx[i].type = htonl (ctx[i].type);
		cmd->ctx[i].name_length = htonl (ctx[i].name_length);
		tpcm_memclear(cmd->ctx[i].name,MAX_DMEASURE_NAME_SIZE);
		tpcm_memcpy (cmd->ctx[i].name, ctx[i].name, ctx[i].name_length);
		cmd->ctx[i].data_length = htonl (ctx[i].data_length);
		trans = ctx[i].data_address;
		trans = htonll(trans);
		tpcm_memcpy(&(cmd->ctx[i].data_address), &trans, 8);
	}

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);
	if (tpcmRspLength (rsp) > sizeof (tpcm_rsp_header_st)){
		if ((int)(*mrLen) < (int)(ntohl (rsp->uiMrLen))){
			httc_util_pr_error ("mresult is not enough (%d < %d)\n", *mrLen, ntohl (rsp->uiMrLen));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*mrLen = ntohl (rsp->uiMrLen);
		tpcm_memcpy (mResult, rsp->uaMresult, *mrLen);
	}
	else{
		*mrLen = 0;
	}
	
out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_collection_and_measure);

#define CMD_DEFAULT_ALLOC_SIZE_COLLECT 53000

int tcsk_collection_and_measure_operate(uint32_t operation, uint32_t ctxNum, 
   	struct collection_context *ctx, uint32_t *tpcmRes, uint32_t *mrLen, unsigned char *mResult)
{
	int i = 0;
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE_COLLECT;
	uint64_t trans = 0;
	collect_measure_req_st *cmd = NULL;
	collect_measure_rsp_st *rsp = NULL;

	if (NULL == (cmd = (collect_measure_req_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE_COLLECT))){
			httc_util_pr_error ("Req Alloc hter!\n");
			return TSS_ERR_NOMEM;
	}
	
	if (NULL == (rsp = (collect_measure_rsp_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE_COLLECT))){
		httc_util_pr_error ("Req Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (collect_measure_req_st) + sizeof (struct collection_context) * ctxNum;
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE_COLLECT){
		httc_util_pr_error ("ctx is too large!\n");
		tdd_free_data_buffer (cmd);
		tdd_free_data_buffer (rsp);
		return TSS_ERR_INPUT_EXCEED;
	}
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_CollectAndMeasureOpera);
	cmd->uiOperation = htonl (operation);
	cmd->uiCtxNumber = htonl (ctxNum);

	for (i = 0; i < ctxNum; i++){
		if (ctx[i].name_length > MAX_DMEASURE_NAME_SIZE){
			httc_util_pr_error ("ctx[%d].name is too long (%d > %d)\n", i, ctx[i].name_length, MAX_DMEASURE_NAME_SIZE);
			ret = TSS_ERR_INPUT_EXCEED;
			goto out;
		}
		cmd->ctx[i].type = htonl (ctx[i].type);
		cmd->ctx[i].name_length = htonl (ctx[i].name_length);
		tpcm_memclear(cmd->ctx[i].name,MAX_DMEASURE_NAME_SIZE);
		tpcm_memcpy (cmd->ctx[i].name, ctx[i].name, ctx[i].name_length);
		cmd->ctx[i].data_length = htonl (ctx[i].data_length);
		trans = ctx[i].data_address;
		trans = htonll(trans);
		tpcm_memcpy(&(cmd->ctx[i].data_address), &trans, 8);
	}

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);
	if (tpcmRspLength (rsp) > sizeof (tpcm_rsp_header_st)){
		if ((int)(*mrLen) < (int)(ntohl (rsp->uiMrLen))){
			httc_util_pr_error ("mresult is not enough (%d < %d)\n", *mrLen, ntohl (rsp->uiMrLen));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*mrLen = ntohl (rsp->uiMrLen);
		tpcm_memcpy (mResult, rsp->uaMresult, *mrLen);
	}
	else{
		*mrLen = 0;
	}
	
out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_collection_and_measure_operate);

