#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "debug.h"
#include "kutils.h"
#include "tcs_error.h"
#include "tcs_config.h"
#include "tpcm_command.h"

#include "tdd.h"
#include "tddl.h"
#include "tcs_tpcm.h"
#include "tcs_bmeasure.h"
#include "tcs_auth_def.h"
#include "tcs_policy_mgmt.h"

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	uint32_t uiStage;
	uint8_t  uaDigest[DEFAULT_HASH_SIZE];
	uint32_t uiObjLen;
	uint8_t  uaObj[0];
}simple_bmeasure_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiPcr;
	uint32_t uiStage;
	uint8_t  uaDigest[DEFAULT_HASH_SIZE];
	uint32_t uiObjLen;
	uint8_t  uaObj[0];
}extern_simple_bmeasure_req_st;

typedef struct get_bm_reference_rsp{
	RESPONSE_HEADER;
	uint32_t num;
	struct boot_ref_item reference[0];
}get_bm_reference_rsp_st; 

typedef struct get_bm_reference_record_rsp{
	RESPONSE_HEADER;
	uint32_t num;
	struct boot_measure_record records[0];
}get_bm_reference_record_rsp_st; 

#pragma pack(pop)

int tpcm_ioctl_update_reference_increment (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	uint32_t ref_type = 0;
	uint32_t object_id = 0;
	int  hash_len = 0;
	int uid_size = 0;
	int auth_size = 0;
	uint8_t hash[DEFAULT_HASH_SIZE] = {0};
	tpcm_req_header_st *cmd = NULL;
	int cmd_opt = sizeof (tpcm_req_header_st);
	int ucmd_opt = sizeof (tpcm_req_header_st);

	uid_size = httc_extract_uid_align4_size (ucmd + ucmd_opt);
	ucmd_opt += uid_size;
	auth_size = httc_extract_auth_align4_size (ucmd + ucmd_opt);
	ucmd_opt += auth_size;

	ref_type = ntohl (*(uint32_t*)(ucmd + ucmd_opt));
	switch (ref_type){
		case RT_BOOT_MEASURE:
			object_id = TPCM_ADMIN_AUTH_POLICY_BOOT_REF;
			break;
		case RT_WHILELIST:
			object_id = TPCM_ADMIN_AUTH_POLICY_INTEGRETY_REF;
			break;
		default:
			httc_util_pr_error ("Invalid reference type :%d\n", ref_type);
			ret = TSS_ERR_PARAMETER;
			goto failure;
	}

	if (0 != (ret = tcs_util_calc_policy_hash (object_id, hash, &hash_len))){
		httc_util_pr_error ("tcs_util_calc_policy_hash hter: %d(0x%x)\n", ret, ret);
		goto failure;
	}

	if (NULL == (cmd = (tpcm_req_header_st *)tdd_alloc_data_buffer (ucmdLen + sizeof(struct tpcm_data) + hash_len))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd_opt = sizeof (tpcm_req_header_st);
	tpcm_memcpy ((void*)cmd + cmd_opt, ucmd + sizeof (tpcm_req_header_st), uid_size + auth_size);
	cmd_opt += uid_size + auth_size;
	cmd_opt += httc_insert_data_align4 ((const char *)hash, hash_len, (void*)cmd + cmd_opt);
	tpcm_memcpy ((void*)cmd + cmd_opt, ucmd + ucmd_opt, ucmdLen - ucmd_opt);
	cmd_opt += ucmdLen - ucmd_opt;

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmd_opt);
	cmd->uiCmdCode = htonl (TPCM_ORD_UpdateSignedReferenceIncrement);

	ret = tpcm_tddl_transmit_cmd (cmd, cmd_opt, rsp, rspLen);
	goto out;

failure:
	((tpcm_rsp_header_st *)rsp)->uiRspTag = htonl (TPCM_TAG_RSP_COMMAND);
	((tpcm_rsp_header_st *)rsp)->uiRspLength = htonl (sizeof (tpcm_rsp_header_st));
	((tpcm_rsp_header_st *)rsp)->uiRspRet = htonl (ret);
	*rspLen = sizeof (tpcm_rsp_header_st);

out:
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;
}

int tcsk_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen, uint32_t *tpcmRes)
{
/**
typedef struct{
	COMMAND_HEADER;
	uint32_t uiStage;
	uint32_t uiNumber;
	uint8_t  aucBm[...];
	uint8_t  uiObjLen;
	uint8_t  uiObj[0];
}bmeasure_req_st; 
*/
	int i = 0;
	int ret = 0;
	uint8_t *buffer = NULL;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint32_t blockLen = num * sizeof (struct physical_memory_block);
	
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	uint8_t *ops = 0;
	uint64_t trans = 0;

	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st*)buffer;
	rsp = (tpcm_rsp_header_st*) (buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (tpcm_req_header_st) + sizeof (stage) + sizeof (num) + blockLen + sizeof (objLen) + sizeof (objAddr);
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		tdd_free_data_buffer (cmd);
		httc_util_pr_error ("block is too large!\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_BootMeasure);

	ops = (uint8_t*)cmd + sizeof (tpcm_req_header_st);

	/** Insert stage */
	*((uint32_t *)ops) = htonl (stage);
	ops += 4;
	/** Insert num */
	*((uint32_t *)ops) = htonl (num);
	ops += 4;
	/** Insert block */
	for (i = 0; i < num; i++){
		trans = htonll((block+i)->physical_addr);
		tpcm_memcpy(ops, &trans, sizeof(uint64_t));
		ops += 8;
		*((uint32_t *)ops) = htonl ((block+i)->length);
		ops += 4;
	}
	/** insert objLen */
	*((uint32_t *)ops) = htonl (objLen);
	ops += 4;
	/** insert objAddress */
	trans = htonll(objAddr);
	tpcm_memcpy(ops, &trans, sizeof(uint64_t));
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);

out:
	if (buffer)	tdd_free_data_buffer (buffer);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_boot_measure);

int tcsk_simple_boot_measure (
		uint32_t stage, uint8_t *digest, uint8_t *obj, uint32_t objLen, uint32_t *tpcmRes)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	simple_bmeasure_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (simple_bmeasure_req_st*)buffer;
	rsp = (tpcm_rsp_header_st*) (buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (simple_bmeasure_req_st) + objLen;
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		tdd_free_data_buffer (buffer);
		ret = TSS_ERR_INPUT_EXCEED;
		httc_util_pr_error ("param size is too large!\n");
		goto out;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SimpleBootMeasure);
	cmd->uiStage = htonl (stage);
	tpcm_memcpy (cmd->uaDigest, digest, DEFAULT_HASH_SIZE);
	cmd->uiObjLen= htonl (objLen);
	tpcm_memcpy (cmd->uaObj, obj, objLen);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);

out:
	if (buffer)	tdd_free_data_buffer (buffer);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_simple_boot_measure);

int tcs_extern_boot_meausre (uint32_t pcr, uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen, uint32_t *tpcmRes)
{
/**
typedef struct{
	COMMAND_HEADER;
	uint32_t uiPcr;
	uint32_t uiStage;
	uint32_t uiNumber;
	uint8_t  aucBm[...];
	uint8_t  uiObjLen;
	uint8_t  uiObj[0];
}bmeasure_req_st; 
*/
	int i = 0;
	int ret = 0;
	uint8_t *buffer = NULL;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint32_t blockLen = num * sizeof (struct physical_memory_block);
	
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	uint8_t *ops = 0;
	uint64_t trans = 0;

	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st*)buffer;
	rsp = (tpcm_rsp_header_st*) (buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (tpcm_req_header_st) + sizeof (stage) + sizeof (num) + blockLen + sizeof (objLen) + sizeof (objAddr);
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		tdd_free_data_buffer (cmd);
		httc_util_pr_error ("block is too large!\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_ExternBootMeasure);

	ops = (uint8_t*)cmd + sizeof (tpcm_req_header_st);

	/** Insert pcr */
	*((uint32_t *)ops) = htonl (pcr);
	ops += 4;
	/** Insert stage */
	*((uint32_t *)ops) = htonl (stage);
	ops += 4;
	/** Insert num */
	*((uint32_t *)ops) = htonl (num);
	ops += 4;
	/** Insert block */
	for (i = 0; i < num; i++){
		trans = htonll((block+i)->physical_addr);
		tpcm_memcpy(ops, &trans, sizeof(uint64_t));
		ops += 8;
		*((uint32_t *)ops) = htonl ((block+i)->length);
		ops += 4;
	}
	/** insert objLen */
	*((uint32_t *)ops) = htonl (objLen);
	ops += 4;
	/** insert objAddress */
	trans = htonll(objAddr);
	tpcm_memcpy(ops, &trans, sizeof(uint64_t));
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);

out:
	if (buffer)	tdd_free_data_buffer (buffer);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcs_extern_boot_meausre);

int tcs_extern_simple_boot_meausre (
		uint32_t pcr, uint32_t stage, uint8_t *digest, uint8_t *obj, uint32_t objLen, uint32_t *tpcmRes)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	extern_simple_bmeasure_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if (NULL == (cmd = (extern_simple_bmeasure_req_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	if (NULL == (rsp = (tpcm_rsp_header_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		if (cmd)	tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (extern_simple_bmeasure_req_st) + objLen;
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		tdd_free_data_buffer (cmd);
		tdd_free_data_buffer (rsp);
		ret = TSS_ERR_INPUT_EXCEED;
		httc_util_pr_error ("param size is too large!\n");
		goto out;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_ExternSimpleBootMeasure);
	cmd->uiPcr = htonl (pcr);
	cmd->uiStage = htonl (stage);
	tpcm_memcpy (cmd->uaDigest, digest, DEFAULT_HASH_SIZE);
	cmd->uiObjLen= htonl (objLen);
	tpcm_memcpy (cmd->uaObj, obj, objLen);
	
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
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcs_extern_simple_boot_meausre);


