#include <linux/kernel.h>
#include <linux/slab.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"

#pragma pack(push, 1)

typedef struct{
	uint64_t udAddress;	/** Physical Address */
	uint32_t uiLength;
}fw_unit_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t uaFwBuf[0];
}fw_upgrade_user_req_st;

typedef struct {
	COMMAND_HEADER;
	uint32_t uiNumber;
	fw_unit_st fw[0];
}fw_upgrade_kernel_req_st;

#pragma pack(pop)


int tpcm_ioctl_firmware_upgrade (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	uint32_t cmdUserLengthOpt = 0;
	uint32_t fwUserLengthRest = 0;
	uint32_t fwLengthOnce = 0;
	uint32_t num = 0;

	uint32_t cmdLen = 0;
	uint64_t udAddress = 0;
	fw_unit_st *fwbuf = NULL;
	fw_upgrade_kernel_req_st *cmd = NULL;

	if (NULL == (cmd = (fw_upgrade_kernel_req_st*)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("fw_upgrade_kernel_req_st alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	if (NULL == (fwbuf = (fw_unit_st*)httc_kzalloc (CMD_DEFAULT_ALLOC_SIZE, GFP_KERNEL))){
		httc_util_pr_error ("fw_unit_st alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	fwUserLengthRest = ((fw_upgrade_user_req_st *)ucmd)->uiCmdLength - sizeof (fw_upgrade_user_req_st);
	do{

		fwbuf[num].udAddress = (unsigned long)httc_kmalloc (PAGE64K, GFP_KERNEL);
		if (!fwbuf[num].udAddress)	{
			httc_util_pr_error ("Kmalloc fwu[%d] hter!\n", num);
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		fwLengthOnce = (fwUserLengthRest < PAGE64K) ? fwUserLengthRest : PAGE64K;
		memcpy ((void *)(unsigned long)(fwbuf[num].udAddress), &((fw_upgrade_user_req_st *)ucmd)->uaFwBuf[cmdUserLengthOpt], fwLengthOnce);
		tpcm_util_cache_flush ((void*)(unsigned long)(fwbuf[num].udAddress), fwLengthOnce);
		fwbuf[num].uiLength = fwLengthOnce;
		num ++;
		cmdUserLengthOpt += fwLengthOnce;
		fwUserLengthRest -= fwLengthOnce;
	}while (fwUserLengthRest);


	cmdLen = sizeof (fw_upgrade_kernel_req_st) + sizeof(fw_unit_st) * num;
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_FirmwareUpgrade);
	cmd->uiNumber = htonl (num);
	for (i = 0; i < num; i++){
		udAddress = htonll (tdd_get_phys_addr((void*)(unsigned long)fwbuf[i].udAddress));
		tpcm_memcpy (&cmd->fw[i].udAddress, &udAddress, 8);
		cmd->fw[i].uiLength = htonl (fwbuf[i].uiLength);
	}

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

out:
	for (i = 0; i < num; i++){
		if (fwbuf[i].udAddress)	httc_kfree ((void*)(unsigned long)fwbuf[i].udAddress);
	}
	if (fwbuf)	httc_kfree (fwbuf);
	if (cmd)	tdd_free_data_buffer (cmd);
	return ret;
}

