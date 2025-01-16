#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>

#include "memdebug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "debug.h"
#include "tdd.h"
#include "tddl.h"
#include "tcs_kernel.h"
#include "tcs_protect.h"
#include "tcs_policy_mgmt.h"
#include "version.h"
#pragma pack(push, 1)
typedef struct get_ptrace_protect_policy_rsp{
	RESPONSE_HEADER;
    int length;
	uint8_t policy[0];
}get_ptrace_protect_policy_rsp_st; 
#pragma pack(pop)

int tcs_ioctl_update_ptrace_protect_policy (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	int length = 0;
	struct ptrace_protect *policy = NULL;
	uint8_t *cmd = NULL;
	
	if (NULL == (cmd = tdd_alloc_data_buffer (ucmdLen))){
		printk ("[%s:%d] Req Alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	tpcm_memcpy (cmd, ucmd, ucmdLen);
	if (0 == (ret = tpcm_tddl_transmit_cmd (cmd, ucmdLen, rsp, (int *)rspLen))){
		if (0 == (ret = tcs_get_ptrace_protect_policy (&policy, &length))){
			ret = tcs_util_set_ptrace_protect_policy (policy, length);
		}
	}
	if (cmd)	tdd_free_data_buffer (cmd);
	if (policy)	httc_vfree (policy);
	return ret;
}


int tcs_get_ptrace_protect_policy(struct ptrace_protect **ptrace_protect, int *length)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_RESPONSE_BUFFER_SIZE;
	int size = 0;
	tpcm_req_header_st *cmd = NULL;
    get_ptrace_protect_policy_rsp_st *rsp = NULL; 

	if (NULL == (cmd = (tpcm_req_header_st *)tdd_alloc_data_buffer (TPCM_COMMAND_BUFFER_SIZE * 2))){
		httc_util_pr_error (" Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	rsp = (get_ptrace_protect_policy_rsp_st *)((void*)cmd + TPCM_COMMAND_BUFFER_SIZE);
	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetPtraceProtectsPolicy);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		printk ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	if (tpcmRspLength (rsp) < sizeof (get_ptrace_protect_policy_rsp_st)){
		printk ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	size = ntohl (rsp->length);
	if (size != (tpcmRspLength (rsp) - sizeof (get_ptrace_protect_policy_rsp_st))){
		printk ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if (size){
		if (NULL == (*ptrace_protect = (struct ptrace_protect *)httc_vmalloc (size))){
			httc_util_pr_error ("mem alloc for ptrace protect policy hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		tpcm_memcpy (*ptrace_protect, rsp->policy, size);
		*length = size;
	}

out:
	if (cmd)	tdd_free_data_buffer (cmd);
	return ret;
}

