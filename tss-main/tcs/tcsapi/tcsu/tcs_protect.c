#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "uutils.h"
#include "tcs_error.h"
#include "tcs_tpcm_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "transmit.h"
#include "tcs_protect.h"
#include "file.h"
#include "tcs_util_policy_update.h"

#pragma pack(push, 1)
typedef struct get_ptrace_protect_policy_rsp{
	RESPONSE_HEADER;
    int length;
	uint8_t policy[0];
}get_ptrace_protect_policy_rsp_st; 
#pragma pack(pop)

int tcs_update_ptrace_protect_policy(struct ptrace_protect_update *update,
				const char *uid, int cert_type, int auth_length, unsigned char *auth)
{
/**	
	struct update_ptrace_protect_policy{
		COMMAND_HEADER;
		struct tpcm_data uid;
		struct tpcm_auth auth;
		struct ptrace_protect_update *update;
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
	
	if (ntohl (update->be_size) != sizeof (struct ptrace_protect_update)){
		return TSS_ERR_PARAMETER;
	}
	if ((!auth && auth_length) || (auth && (auth_length <= 0)))	return TSS_ERR_PARAMETER;
	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;
	
	policy_size = ntohl (update->be_size) + ntohl (update->data[0].be_total_length);
	if (policy_size > TPCM_POLICY_UPDATE_CMD_LIMIT){
		httc_util_pr_error ("Too large policy_size (%d > %d)\n",
				policy_size, TPCM_POLICY_UPDATE_CMD_LIMIT);
		return TSS_ERR_INPUT_EXCEED;
	}
	size = policy_size
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (buffer = httc_malloc (sizeof (tpcm_req_header_st) + size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_req_header_st *)buffer;
	rsp = (tpcm_rsp_header_st *)((void*)cmd + size);

	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4) */
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (cert_type, auth_length, auth, (void*)cmd + cmdLen);
	memcpy ((void*)cmd + cmdLen, update, policy_size);
	cmdLen += policy_size;
	
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_UpdatePtraceProtectsPolicy);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer) httc_free (buffer);
	return ret;
}

int tcs_get_ptrace_protect_policy(struct ptrace_protect **ptrace_protect, int *length)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_RESPONSE_BUFFER_SIZE;
	tpcm_req_header_st *cmd = NULL;
    get_ptrace_protect_policy_rsp_st *rsp = NULL; 

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (TPCM_COMMAND_BUFFER_SIZE * 2))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	rsp = (get_ptrace_protect_policy_rsp_st *)((void*)cmd + TPCM_COMMAND_BUFFER_SIZE);
	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetPtraceProtectsPolicy);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;
	if (tpcmRspLength (rsp) < sizeof (get_ptrace_protect_policy_rsp_st)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	*length = ntohl (rsp->length);
	
	if (*length != (tpcmRspLength (rsp) - sizeof (get_ptrace_protect_policy_rsp_st))){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if (*length){
		if (NULL == (*ptrace_protect = (struct ptrace_protect *)httc_malloc (*length))){
			httc_util_pr_error ("mem alloc for ptrace protect policy error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*ptrace_protect, rsp->policy, *length);
	}

out:
	if (cmd)	httc_free (cmd);
	return ret;
}

