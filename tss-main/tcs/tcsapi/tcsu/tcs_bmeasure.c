#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "uutils.h"
#include "tcs_tpcm.h"
#include "transmit.h"
#include "tpcm_command.h"

#include "tcs_error.h"
#include "tcs_constant.h"
#include "tcs_config.h"
#include "tcs_bmeasure.h"

#include "mem.h"
#include "debug.h"
#include "convert.h"

#pragma pack(push, 1)

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

typedef struct update_bm_reference_rsp{
	COMMAND_HEADER;
}update_bm_reference_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uiStage;
	uint8_t  uaDigest[DEFAULT_HASH_SIZE];
	uint32_t uiObjLen;
	uint8_t  uaObj[0];
}simple_bmeasure_req_st;


#pragma pack(pop)

int tcs_update_boot_measure_references(struct boot_references_update *references,
		const char *uid, int auth_type, int auth_length, unsigned char *auth)
{
/**	
	struct file_integrity_update_req{
		COMMAND_HEADER;
		struct tpcm_data uid;
		struct tpcm_auth auth;
		uint32_t type;
		struct boot_references_update ref;
	};
*/
	int ret = 0;
	int size = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	update_bm_reference_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	struct boot_references_update *ref = NULL;
	int ref_size = 0;
	int uid_len = 0;
	int auth_len = 0;
	
	if (ntohl (references->be_size) != sizeof (struct boot_references_update)){
		httc_util_pr_error ("Unmatched structure (%d != %ld)\n",
			ntohl (references->be_size), (long int)sizeof (struct boot_references_update));
		return TSS_ERR_PARAMETER;
	}
	if ((!auth && auth_length) || (auth && (auth_length <= 0)))	return TSS_ERR_PARAMETER;

	ref_size = ntohl (references->be_size) + ntohl (references->be_data_length);
	if (ref_size > TPCM_BMEASURE_REFERENCE_UPDATE_LIMIT){
		httc_util_pr_error ("Too large reference (%d > %d)\n",
				ref_size, TPCM_BMEASURE_REFERENCE_UPDATE_LIMIT);
		return TSS_ERR_INPUT_EXCEED;
	}

	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;

	size = sizeof (update_bm_reference_req_st) + ref_size
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (cmd = httc_malloc (size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tpcm_rsp_header_st *)((void*)cmd + CMD_DEFAULT_ALLOC_SIZE);
	cmdLen = sizeof (update_bm_reference_req_st);

	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + cmdLen);



	/** Insert reference type */
	*(uint32_t *)((void*)cmd + cmdLen) = htonl (RT_BOOT_MEASURE);
	cmdLen += (sizeof (uint32_t));

	/** Insert references */
	ref = (struct boot_references_update *)((void*)cmd + cmdLen);
	memcpy (ref, references, ref_size);
	cmdLen += ref_size;

	/** Insert cmd header */
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_UpdateSignedReferenceIncrement);

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
	if (cmd)	httc_free (cmd);
	return ret;
}

int tcs_get_boot_measure_references(struct boot_ref_item **references,int *num, int *length)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_BMEASURE_REFERENCE_READ_LIMIT;
	tpcm_req_header_st *cmd = NULL;
	struct get_bm_reference_rsp *rsp = NULL;
	
	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	if (NULL == (rsp = (struct get_bm_reference_rsp *)httc_malloc (rspLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}
	
	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetBootMeasureReferences);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (tpcmRspLength(rsp) < sizeof (struct get_bm_reference_rsp)){
		httc_util_pr_error ("Invalid response stream\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;
	*length = tpcmRspLength (rsp) - sizeof (struct get_bm_reference_rsp);
	*num = ntohl (rsp->num);
	if (*length){
		if (NULL == (*references = (struct boot_ref_item *)httc_malloc (*length))){
			httc_util_pr_error ("mem alloc for boot_records error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*references, rsp->reference, *length);
	}

out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	return ret;
}

int tcs_get_boot_measure_records (struct boot_measure_record **boot_records, int *num, int *length)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = TPCM_BMEASURE_RECORD_READ_LIMIT;
	tpcm_req_header_st *cmd = NULL;
	struct get_bm_reference_record_rsp *rsp = NULL;

	if (NULL == (cmd = (tpcm_req_header_st *)httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (struct get_bm_reference_record_rsp *)httc_malloc (rspLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		httc_free (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof (tpcm_req_header_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetBootMeasureRecord);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 != (ret = tpcmRspRetCode (rsp)))	goto out;

	*length = tpcmRspLength (rsp) - sizeof (struct get_bm_reference_record_rsp);
	*num = ntohl (rsp->num);
	if (*length){
		if (NULL == (*boot_records = (struct  boot_measure_record *)httc_malloc (*length))){
			httc_util_pr_error ("mem alloc for boot_records error!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy (*boot_records, rsp->records, *length);
	}

out:
	if (cmd)	httc_free (cmd);
	if (rsp)	httc_free (rsp);
	return ret;
}

int tcs_boot_measure (uint32_t stage, uint32_t num,
			struct physical_memory_block *block, uint64_t objAddr, uint32_t objLen)
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

	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st*)buffer;
	rsp = (tpcm_rsp_header_st*) (buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (tpcm_req_header_st) + sizeof (stage) + sizeof (num) + blockLen + sizeof (objLen) + sizeof (objAddr);
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		httc_free (cmd);
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
		memcpy(ops, &trans, sizeof(uint64_t));
		ops += 8;
		*((uint32_t *)ops) = htonl ((block+i)->length);
		ops += 4;
	}
	/** insert objLen */
	*((uint32_t *)ops) = htonl (objLen);
	ops += 4;
	/** insert objAddress */
	trans = htonll(objAddr);
	memcpy(ops, &trans, sizeof(uint64_t));
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer)	httc_free (buffer);
	return ret;
}

int tcs_simple_boot_measure (
		uint32_t stage, uint8_t *digest, uint8_t *obj, uint32_t objLen)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	uint32_t cmdLen = 0;
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	simple_bmeasure_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (simple_bmeasure_req_st*)buffer;
	rsp = (tpcm_rsp_header_st*) (buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (simple_bmeasure_req_st) + objLen;
	if ((int)cmdLen > (int)CMD_DEFAULT_ALLOC_SIZE){
		httc_free (buffer);
		ret = TSS_ERR_INPUT_EXCEED;
		httc_util_pr_error ("param size is too large!\n");
		goto out;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SimpleBootMeasure);
	cmd->uiStage = htonl (stage);
	memcpy (cmd->uaDigest, digest, DEFAULT_HASH_SIZE);
	cmd->uiObjLen= htonl (objLen);
	memcpy (cmd->uaObj, obj, objLen);
	
	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	
	ret = tpcmRspRetCode (rsp);

out:
	if (buffer)	httc_free (buffer);
	//DEBUG (ret);
	return ret;
}


