#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/io.h>

#include "memdebug.h"
#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tdd.h"
#include "tddl.h"
#include "tcs_kernel.h"

uint8_t** tcs_util_get_tcs_mmap_addr_list (void);
int tcs_util_get_tcs_mmap_addr_num (void);
int tcs_util_get_tcs_mmap_seg_limit (void);


#pragma pack(push, 1)

typedef struct get_progress_reference_user_req{
	COMMAND_HEADER;
	uint32_t size;
}get_progress_reference_user_req_st; 

typedef struct{
	COMMAND_HEADER;
	uint32_t num;
	uint32_t limit;
	uint64_t address[0];
}get_progress_reference_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ui_path_len;
	uint64_t ud_path_addr;
	uint32_t ui_type;
	uint32_t ui_block_number;
	struct physical_memory_block block[0];
}imeasure_req_st; 

typedef struct{
	RESPONSE_HEADER;
	uint32_t ui_mr_len;		/** Measure result length */
	uint8_t  ua_mresult[0];	/** Measure result */
}imeasure_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ui_path_len;
	uint64_t ud_path_addr;
	uint32_t ui_type;
	uint32_t ui_hash_length;
	uint8_t  ua_hash[0];
}imeasure_simple_req_st; 

#pragma pack(pop)

int tpcm_ioctl_read_file_integrity (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen)
{
	int i,ret = 0;
	int cmdLen = 0;
	uint64_t trans = 0;
	void **ref_addr = NULL;
	get_progress_reference_req_st *cmd = NULL;

	int seg_size = 0;
	int size = ((get_progress_reference_user_req_st*)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();

	if (NULL == (ref_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		httc_util_pr_error ("tddl_get_mmap_virt_addr hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (cmd = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("get_file_integrity_req_st alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(ref_addr[i]));
		tpcm_memcpy(&(cmd->address[i]), &trans, sizeof(uint64_t));
		left_size -= seg_size;
	}

	cmdLen = sizeof (get_progress_reference_req_st) + seg_num * 8;
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetProgressReference);
	cmd->num = htonl (seg_num);
	cmd->limit = htonl (seg_limit);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

#ifdef __aarch64__
	if (0 == tpcmRspRetCode (rsp)){
		seg_size = size;
		for (i = 0; i < seg_num; i++){
			seg_size = (size < seg_limit) ? size : seg_limit;
			httc_arch_invalidate_pmem (ref_addr[i], seg_size);
			size -= seg_size;
		}
	}
#endif

	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

int tcsk_integrity_measure (uint32_t path_len, void *path_addr, uint32_t type,
		uint32_t num_block, struct physical_memory_block *blocks, uint32_t *tpcmRes, uint32_t *mrLen, unsigned char *mresult)
{
#define INTERCEPT_MEASURE_CMD_SIZE	(512*1024)	/** 512K */

	int i = 0;
	int ret = 0;
	uint64_t udAddress = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	imeasure_req_st *cmd = NULL;
	imeasure_rsp_st *rsp = NULL;

	cmdLen = sizeof (imeasure_req_st) + sizeof (struct physical_memory_block) * num_block;
	if ((int)cmdLen > (int)INTERCEPT_MEASURE_CMD_SIZE){
		httc_util_pr_error ("munit is too large!\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if (NULL == (cmd = (imeasure_req_st *)tdd_alloc_data_buffer (cmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TPCM_ERROR_TIMEOUT;
	}
	if (NULL == (rsp = (imeasure_rsp_st *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TPCM_ERROR_TIMEOUT;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_InterceptMeasure);
	cmd->ui_path_len = htonl (path_len);
	udAddress = htonll ((uint64_t)tdd_get_phys_addr((void *)path_addr));
	tpcm_memcpy (&cmd->ud_path_addr, &udAddress, 8);
	cmd->ui_type = htonl (type);
	cmd->ui_block_number = htonl (num_block);
	for (i = 0; i < num_block; i++){
		udAddress =  htonll((blocks+i)->physical_addr);
		tpcm_memcpy (&cmd->block[i].physical_addr, &udAddress, 8);
		cmd->block[i].length = htonl ((blocks+i)->length);
	}
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);
	if (tpcmRspLength (rsp) > sizeof (tpcm_rsp_header_st)){
		if ((int)(*mrLen) < (int)(ntohl (rsp->ui_mr_len))){
			httc_util_pr_error ("mresult is not enough (%d < %d)\n", *mrLen, ntohl (rsp->ui_mr_len));
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*mrLen = ntohl (rsp->ui_mr_len);
		memcpy (mresult, rsp->ua_mresult, *mrLen);
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
EXPORT_SYMBOL_GPL (tcsk_integrity_measure);

int tcsk_integrity_measure_simple (
		int path_len, void *path_addr, uint32_t type, int hash_length, unsigned char *hash, uint32_t *tpcmRes)
{
	int ret = 0;
	uint64_t udAddress = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	imeasure_simple_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (cmd = (imeasure_simple_req_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TPCM_ERROR_TIMEOUT;
	}
	if (NULL == (rsp = (tpcm_rsp_header_st *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TPCM_ERROR_TIMEOUT;
	}

	cmdLen = sizeof (imeasure_simple_req_st) + hash_length;
	if (cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		httc_util_pr_error ("cmd is too large (%d > %d)\n", cmdLen, (int)CMD_DEFAULT_ALLOC_SIZE);
		tdd_free_data_buffer (cmd);
		tdd_free_data_buffer (rsp);
		return TSS_ERR_INPUT_EXCEED;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_InterceptMeasureSimple);
	cmd->ui_path_len = htonl (path_len);
	udAddress = htonll ((uint64_t)tdd_get_phys_addr((void *)path_addr));
	tpcm_memcpy (&cmd->ud_path_addr, &udAddress, 8);
	cmd->ui_type = htonl (type);
	cmd->ui_hash_length = htonl (hash_length);
	tpcm_memcpy (cmd->ua_hash, hash, hash_length);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	*tpcmRes = tpcmRspRetCode (rsp);

out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_integrity_measure_simple);

static int generate_integrity_measure_param (
			uint8_t *imKey, uint32_t imKeyLen, uint8_t *data, uint32_t dataLen,
			uint8_t **vmkey, struct physical_memory_block **block, struct physical_memory_block **vblock, uint32_t *blockNum)
{
	int i = 0;
	int ret = 0;
	unsigned int imLengthOnce = 0;
	unsigned int imUserLengthRest = 0;
	unsigned int imLengthOpt = 0;
	uint8_t *pst_vmkey = NULL;
	struct physical_memory_block *pst_block = NULL;
	struct physical_memory_block *pst_vblock = NULL;

	if (NULL == (pst_vmkey = (uint8_t *)httc_kmalloc (PAGE_SIZE, GFP_KERNEL))){
		httc_util_pr_error ("Malloc vmKey hter\n");
		return TSS_ERR_NOMEM;
	}
	memcpy (pst_vmkey, imKey, imKeyLen);
	tpcm_util_cache_flush (pst_vmkey, imKeyLen);

	*blockNum = (dataLen % PAGE64K) ? (dataLen / PAGE64K + 1) : (dataLen / PAGE64K);
	if (NULL == (pst_block = (struct physical_memory_block *)httc_kmalloc (sizeof (struct physical_memory_block) * (*blockNum), GFP_KERNEL))){
		httc_util_pr_error ("Malloc munit hter\n");
		return TSS_ERR_NOMEM;
	}	

	if (NULL == (pst_vblock = (struct physical_memory_block *)httc_kmalloc (sizeof (struct physical_memory_block) * (*blockNum), GFP_KERNEL))){
		httc_util_pr_error ("Malloc vblock hter\n");
		httc_kfree (pst_block);
		return TSS_ERR_NOMEM;
	}

	imUserLengthRest = dataLen;
	do {

		if (0 == (pst_vblock[i].physical_addr = (unsigned long)httc_kmalloc (PAGE64K, GFP_KERNEL)))	{
			httc_util_pr_error ("Kmalloc munit[%d] hter!\n", i);
			ret = TSS_ERR_NOMEM;
			goto err;
		}

		imLengthOnce = (imUserLengthRest < PAGE64K) ? imUserLengthRest : PAGE64K;
		memcpy ((void *)(unsigned long)(pst_vblock[i].physical_addr), &data[imLengthOpt], imLengthOnce);
		tpcm_util_cache_flush ((void*)(unsigned long)(pst_vblock[i].physical_addr), imLengthOnce);
		pst_block[i].physical_addr = htonll (tdd_get_phys_addr((void*)(unsigned long)pst_vblock[i].physical_addr));
		pst_block[i].length = htonl (imLengthOnce);
		i ++;
		imLengthOpt += imLengthOnce;
		imUserLengthRest -= imLengthOnce;
	}while (imUserLengthRest);

	*vmkey = pst_vmkey;
	*block = pst_block;
	*vblock = pst_vblock;
	
	return 0;

err:
	if (pst_vmkey) httc_kfree (pst_vmkey);
	if (pst_block) httc_kfree (pst_block);
	while (i--)	if (pst_vblock[i].physical_addr) httc_kfree ((void*)(unsigned long)pst_vblock[i].physical_addr);
	if (pst_vblock) httc_kfree (pst_vblock);	
	return ret;
}

static void release_integrity_measure_param (uint8_t *vmkey, struct physical_memory_block *block, struct physical_memory_block *vblock, uint32_t blockNum)
{
	if (vmkey) httc_kfree (vmkey);
	if (block) httc_kfree (block);
	while (blockNum--)	if (vblock[blockNum].physical_addr) httc_kfree ((void*)(unsigned long)vblock[blockNum].physical_addr);
	if (vblock) httc_kfree (vblock);
}

int tpcm_ioctl_integrity_measure (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	uint32_t op = 0;
	uint8_t *imKey = NULL;
	uint32_t imKeyLen = 0;
	uint32_t type = 0;
	uint8_t *data = NULL;
	uint32_t dataLen = 0;
	uint32_t blockNum = 0;
	uint8_t *vmKey = NULL;
	struct physical_memory_block *block = NULL;
	struct physical_memory_block *vblock = NULL;
	uint64_t udAddress = 0;
	uint32_t cmdLen = 0;
	imeasure_req_st *cmd = NULL;

	op = sizeof (tpcm_req_header_st);
	
	/** Get imKey && imKeyLen */
	imKeyLen = *((uint32_t *)(ucmd + op));
	op += 4;
	imKey = ucmd + op;
	op += imKeyLen;

	/** Get im type */
	type = *((uint32_t *)(ucmd + op));
	op += 4;
	
	/** Get data && dataLen */
	dataLen = *((uint32_t *)(ucmd + op));
	op += 4;
	data = ucmd + op;
	op += dataLen;

	if (0 != (ret = generate_integrity_measure_param (imKey, imKeyLen, data, dataLen, &vmKey, &block, &vblock, &blockNum))){
		httc_util_pr_error ("generate_intercept_measure_param hter!\n");
		return ret;
	}

	cmdLen = sizeof (imeasure_req_st) + sizeof (struct physical_memory_block) * blockNum;
	if ((int)cmdLen > (int)INTERCEPT_MEASURE_CMD_SIZE){
		httc_util_pr_error ("munit is too large!\n");
		ret = TSS_ERR_INPUT_EXCEED;
		goto out;
	}

	if (NULL == (cmd = (imeasure_req_st *)tdd_alloc_data_buffer (cmdLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		ret = TPCM_ERROR_TIMEOUT;
		goto out;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_InterceptMeasure);
	cmd->ui_path_len = htonl (imKeyLen);
	udAddress = htonll ((uint64_t)tdd_get_phys_addr((void *)vmKey));
	tpcm_memcpy (&cmd->ud_path_addr, &udAddress, 8);
	cmd->ui_type = htonl (type);
	cmd->ui_block_number = htonl (blockNum);
	tpcm_memcpy (cmd->block, block, sizeof (struct physical_memory_block) * blockNum);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

out:
	release_integrity_measure_param (vmKey, block, vblock, blockNum);
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

