#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "file.h"
#include "convert.h"
#include "uutils.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "transmit.h"
#include "tcs_dmeasure.h"
#include "tcs_util_policy_update.h"

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

#pragma pack (pop)

int tcs_update_dmeasure_policy(struct dmeasure_policy_update *policy,
		const char *uid,int auth_type, int auth_length, unsigned char *auth)
{
/**	
	struct set_dmeasure_policy_req{
		COMMAND_HEADER;
		struct tpcm_data uid;
		struct tpcm_auth auth;
		struct dmeasure_policy_update *policy;
	};
*/
	int ret = 0;
	int size = 0, policy_size = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	int uid_len = 0;
	int auth_len = 0;
	
	if (ntohl (policy->be_size) != sizeof (struct dmeasure_policy_update)){
		return TSS_ERR_PARAMETER;
	}
	if ((!auth && auth_length) || (auth && (auth_length <= 0)))	return TSS_ERR_PARAMETER;

	policy_size = ntohl (policy->be_size) + ntohl (policy->be_data_length);
	if (policy_size > TPCM_POLICY_UPDATE_CMD_LIMIT){
		httc_util_pr_error ("Too large policy_size (%d > %d)\n",
				policy_size, TPCM_POLICY_UPDATE_CMD_LIMIT);
		return TSS_ERR_INPUT_EXCEED;
	}

	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;	
	size = policy_size
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (buffer = httc_malloc (sizeof (tpcm_req_header_st) + size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_req_header_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + size);

	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + cmdLen);
	memcpy ((void*)cmd + cmdLen, policy, policy_size);
	cmdLen += policy_size;
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetSignDMeasurePolicy);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n",tpcmRspTag(rsp));
		goto out;
	}
	if (tpcmRspLength (rsp) != sizeof (tpcm_rsp_header_st)){
		httc_util_pr_error ("Invalid tpcm response.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer) httc_free (buffer);
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

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (TPCM_COMMAND_BUFFER_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (struct get_dm_policy_rsp *)httc_malloc (rspLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetDmeasurePolicy);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

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
		if (NULL == (*policy = (struct dmeasure_policy_item *)httc_malloc (policy_size))){
			httc_util_pr_error ("mem alloc for dmeasure_policy_item error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*policy, rsp->policy, policy_size);
	}
	*length = policy_size;

out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	return ret;
}
int tcs_update_dmeasure_process_policy(struct dmeasure_process_policy_update *policy,
											const char *uid,int auth_type,
										   int auth_length,unsigned char *auth)
{
	int ret = 0;
	int size = 0, policy_size = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	int uid_len = 0;
	int auth_len = 0;
	
	if (ntohl (policy->be_size) != sizeof (struct dmeasure_process_policy_update)){
		return TSS_ERR_PARAMETER;
	}
	if ((!auth && auth_length) || (auth && (auth_length <= 0)))	return TSS_ERR_PARAMETER;
	
	policy_size = ntohl (policy->be_size) + ntohl (policy->be_data_length);
	if (policy_size > TPCM_POLICY_UPDATE_CMD_LIMIT){
		httc_util_pr_error ("Too large policy_size (%d > %d)\n",
				policy_size, TPCM_POLICY_UPDATE_CMD_LIMIT);
		return TSS_ERR_INPUT_EXCEED;
	}

	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;	
	size = policy_size
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (buffer = httc_malloc (sizeof (tpcm_req_header_st) + size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_req_header_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + size);

	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + cmdLen);
	memcpy ((void*)cmd + cmdLen, policy, policy_size);
	cmdLen += policy_size;
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_UpdateDmeasureProcessPolicy);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (tpcmRspLength (rsp) != sizeof (tpcm_rsp_header_st)){
		httc_util_pr_error ("Invalid tpcm response.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer) httc_free (buffer);
	return ret;
}

int tcs_get_dmeasure_process_policy(struct dmeasure_process_item **policy,int *item_count,int *length)//proc 导出
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_RESPONSE_BUFFER_SIZE;
	tpcm_req_header_st *cmd = NULL;
    get_dm_process_policy_rsp_st *rsp = NULL; 

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (TPCM_COMMAND_BUFFER_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (struct get_dm_process_policy_rsp *)httc_malloc (rspLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetDmeasureProcessPolicy);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

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
		if (NULL == (*policy = (struct dmeasure_process_item *)httc_malloc (*length))){
			httc_util_pr_error ("mem alloc for dmeasure_process_item error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*policy, rsp->policy, *length);
	}

out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	return ret;
}

