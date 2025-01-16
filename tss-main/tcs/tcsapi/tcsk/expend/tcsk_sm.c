#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/pgtable.h>


#include "memdebug.h"
#include "debug.h"
#include "tddl.h"
#include "tdd.h"
#include "tcs_error.h"
#include "kutils.h"
#include "tcs_config.h"
#include "tcs_constant.h"
#include "tpcm_command.h"
#include "tcsk_sm.h"


#define SEG_LIMIT_SIZE (64*1024)

typedef unsigned char SM3_CONTEXT[512];

#pragma pack(push, 1)

typedef struct{
	uint64_t address;	/** Physical Address */
	uint32_t length;
}addr_seg_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t seg_num;
	addr_seg_st seg[0];
}sm3_req_st;

typedef struct
{
	RESPONSE_HEADER;
	uint8_t digest[DEFAULT_HASH_SIZE];
}sm3_rsp_st;

typedef struct{
	SM3_CONTEXT context;
	int datalen;
	uint8_t data[SEG_LIMIT_SIZE];
} tcs_sm3_context_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t ctx_len;
	uint8_t ctx[0];
}sm3_init_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ctx_len;
	SM3_CONTEXT ctx;
	uint32_t seg_num;
	addr_seg_st seg[0];
}sm3_update_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t ctx_len;
	uint8_t ctx[0];
}sm3_update_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ctx_len;
	SM3_CONTEXT ctx;
	addr_seg_st seg;
}sm3_finish_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}sm3_finish_rsp_st;

#pragma pack(pop)

int tcsk_sm3 (const uint8_t *input, int ilen, uint8_t *output, int *olen)
{
	int i = 0;
	int ret = 0;
	int opt = 0;
	sm3_req_st *req = NULL;
	sm3_rsp_st *rsp = NULL;
	addr_seg_st *seg = NULL;
	addr_seg_st *vseg = NULL;
	int len_once = 0;
	int len_rest = ilen;
	int seg_num = ilen / SEG_LIMIT_SIZE + (((ilen % SEG_LIMIT_SIZE) != 0) ? 1 : 0);
	int reqLen = sizeof (sm3_req_st) + seg_num * sizeof (addr_seg_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;

	if(ilen > TPCM_SM3_LIMIT){
		httc_util_pr_error("tcs sm3 input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if (NULL == (req = tdd_alloc_data_buffer (reqLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	if (NULL == (vseg = httc_kmalloc (seg_num * sizeof (addr_seg_st), GFP_KERNEL))){
		httc_util_pr_error ("Vseg Alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	do {
		len_once = MIN (len_rest, SEG_LIMIT_SIZE);
		httc_util_pr_dev ("len_rest: %d, len_once: %d\n", len_rest, len_once);
		vseg[i].length = len_once;
		if (0 == (vseg[i].address = (uint64_t)httc_kmalloc (vseg[i].length, GFP_KERNEL))){
			httc_util_pr_error ("Vseg Alloc hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		memcpy ((char *)vseg[i].address, input+opt, len_once);
		tpcm_util_cache_flush ((char *)vseg[i].address, len_once);
		seg = &req->seg[i];
		tpcm_memcpy_u32 (&seg->length, htonl (vseg[i].length));
		tpcm_memcpy_u64 (&seg->address, htonll (tdd_get_phys_addr((void*)vseg[i].address)));
		opt += len_once;
		len_rest -= len_once;
		i++;
	}while (len_rest);

	
	req->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl (reqLen);
	req->uiCmdCode = htonl (TPCM_ORD_SM3);
	req->seg_num = htonl (seg_num);

	if (0 != (ret = tpcm_tddl_transmit_cmd (req, reqLen, rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if ((ret = tpcmRspRetCode (rsp))) goto out;
	if(tpcmReqLength(rsp) != sizeof(sm3_rsp_st)){
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_rsp_st), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	tpcm_memcpy(output,rsp->digest,DEFAULT_HASH_SIZE);
	*olen = DEFAULT_HASH_SIZE;

out:

	if (vseg){
		while (i--)	{if (vseg[i].address) httc_kfree ((void*)vseg[i].address);}
		httc_kfree ((void*)vseg);
	}
	if (req) tdd_free_data_buffer (req);
	if (rsp) tdd_free_data_buffer (rsp);

	return ret;
}
EXPORT_SYMBOL (tcsk_sm3);

int tcsk_sm3_init (void** ctx)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *req = NULL;
	sm3_init_rsp_st *rsp = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	tcs_sm3_context_st *cntx = NULL;

	if (NULL == (cntx = httc_kmalloc (sizeof (tcs_sm3_context_st), GFP_KERNEL))){
		httc_util_pr_error ("Context Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		httc_kfree (cntx);
		return TSS_ERR_NOMEM;
	}
	req = (tpcm_req_header_st*)buffer;
	rsp = (sm3_init_rsp_st*)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	req->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl (sizeof (tpcm_req_header_st));
	req->uiCmdCode = htonl (TPCM_ORD_SM3_INIT);

	if (0 != (ret = tpcm_tddl_transmit_cmd (req, sizeof (tpcm_req_header_st), rsp, &rspLen))) goto err;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto err;
	}
	if ((ret = tpcmRspRetCode (rsp))) goto err;
	if(tpcmReqLength(rsp) <= sizeof(sm3_init_rsp_st)){
		httc_util_pr_error ("hter response (length:%d < length:%lu)\n",
							 tpcmReqLength(rsp), (long int)sizeof(sm3_init_rsp_st));
		ret = TSS_ERR_BAD_RESPONSE;
		goto err;
	}
	if(tpcmReqLength(rsp) != (sizeof(sm3_init_rsp_st) + ntohl (rsp->ctx_len))){
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_init_rsp_st) + ntohl (rsp->ctx_len), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto err;
	}
	if (ntohl (rsp->ctx_len) > sizeof (SM3_CONTEXT)){
		httc_util_pr_error("tcs sm3 context is not enough (%d < %ld)\n", ntohl (rsp->ctx_len), (long int)sizeof (SM3_CONTEXT));
		ret = TSS_ERR_OUTPUT_EXCEED;
		goto err;
	}

	tpcm_memcpy (cntx->context, (void*)rsp->ctx, ntohl (rsp->ctx_len));
	cntx->datalen = 0;
	*ctx = cntx;
	goto out;

err:
	if (cntx) httc_kfree (cntx);
out:
	if (buffer) tdd_free_data_buffer (buffer);
	return ret;	
}
EXPORT_SYMBOL (tcsk_sm3_init);
	
int tcsk_sm3_update (void* ctx, const uint8_t *input, int ilen)
{
	int i = 0;
	int ret = 0;
	int opt = 0;
	sm3_update_req_st *req = NULL;
	sm3_update_rsp_st *rsp = NULL;
	addr_seg_st *seg = NULL;
	addr_seg_st *vseg = NULL;
	int len_once = 0;
	int len_rest;
	int seg_num;
	int reqLen;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	int next_len = 0;
	tcs_sm3_context_st *cntx = (tcs_sm3_context_st*)ctx;
	int update_len = 0;
	int total_len = ilen + cntx->datalen;
	
	if(ilen > TPCM_SM3_LIMIT){
		httc_util_pr_error("tcs sm3 update input datalen too long\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	if (total_len <= SEG_LIMIT_SIZE){
		memcpy (cntx->data + cntx->datalen, input, ilen);
		cntx->datalen += ilen;
		return TSS_SUCCESS;
	}

	next_len = total_len % SEG_LIMIT_SIZE;
	update_len = total_len - next_len;
	
	len_rest = update_len;
	seg_num = update_len / SEG_LIMIT_SIZE + (((update_len % SEG_LIMIT_SIZE) != 0) ? 1 : 0);
	reqLen = sizeof (sm3_update_req_st) + seg_num * sizeof (addr_seg_st);

	httc_util_pr_dev ("total_len: %d, update_len: %d, next_len: %d\n", total_len, update_len, next_len);

	if (NULL == (req = (sm3_update_req_st *)tdd_alloc_data_buffer (reqLen))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (sm3_update_rsp_st *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	if (NULL == (vseg = httc_kmalloc (seg_num * sizeof (addr_seg_st), GFP_KERNEL))){
		httc_util_pr_error ("Vseg Alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		goto out;
	}
	memset (vseg, 0, seg_num * sizeof (addr_seg_st));
	
	do {
		len_once = MIN (len_rest, SEG_LIMIT_SIZE);
		httc_util_pr_dev ("i: %d, len_rest: %d, len_once: %d\n", i, len_rest, len_once);
		vseg[i].length = len_once;
		if (0 == (vseg[i].address = (uint64_t)httc_kmalloc (vseg[i].length, GFP_KERNEL))){
			httc_util_pr_error ("Vseg Alloc hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		if (i == 0){
			if (cntx->datalen)
				memcpy ((char *)vseg[i].address, cntx->data, cntx->datalen);
			if (len_once - cntx->datalen)
				memcpy ((char *)vseg[i].address + cntx->datalen, input, len_once - cntx->datalen);
			opt += len_once - cntx->datalen;
		}else{
			memcpy ((char *)vseg[i].address, input+opt, len_once);
			opt += len_once;
		}
		tpcm_util_cache_flush ((char *)vseg[i].address, len_once);
		seg = &req->seg[i];
		tpcm_memcpy_u32 (&seg->length, htonl (vseg[i].length));
		tpcm_memcpy_u64 (&seg->address, htonll (tdd_get_phys_addr((void*)vseg[i].address)));
		len_rest -= len_once;
		i++;
	}while (len_rest);

	req->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl (reqLen);
	req->uiCmdCode = htonl (TPCM_ORD_SM3_UPDATE);
	req->ctx_len = htonl (sizeof (SM3_CONTEXT));
	tpcm_memcpy ((void*)req->ctx, (void*)ctx, sizeof (SM3_CONTEXT));
	req->seg_num = htonl (seg_num);

	if (0 != (ret = tpcm_tddl_transmit_cmd (req, reqLen, rsp, &rspLen))) goto out;
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	
	if ((ret = tpcmRspRetCode (rsp))) goto out;
	
	if(tpcmReqLength(rsp) <= sizeof(sm3_update_rsp_st)){
		httc_util_pr_error ("hter response (length:%d < length:%ld)\n",
							 tpcmReqLength(rsp), (long int)sizeof(sm3_update_rsp_st));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	if(tpcmReqLength(rsp) != (sizeof(sm3_update_rsp_st) + ntohl (rsp->ctx_len))){
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_update_rsp_st) + ntohl (rsp->ctx_len), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	if (ntohl (rsp->ctx_len) > sizeof (SM3_CONTEXT)){
		httc_util_pr_error("tcs sm3 context is not enough (%d < %ld)\n", ntohl (rsp->ctx_len), (long int)sizeof (SM3_CONTEXT));
		return TSS_ERR_OUTPUT_EXCEED;
	}
	tpcm_memcpy (cntx->context, (void*)rsp->ctx, ntohl (rsp->ctx_len));
	
	if (next_len){
		memcpy (cntx->data + cntx->datalen, input + ilen - next_len, next_len);
		cntx->datalen = next_len;
	}else{
		cntx->datalen = 0;
	}

	httc_util_pr_dev ("cntx->datalen: %d\n", cntx->datalen);

out:
	if (vseg){
		while (i--)	{if (vseg[i].address) httc_kfree ((void*)vseg[i].address);}
		httc_kfree ((void*)vseg);
	}
	if (req) tdd_free_data_buffer (req);
	if (rsp) tdd_free_data_buffer (rsp);

	return ret;
}
EXPORT_SYMBOL (tcsk_sm3_update);

int tcsk_sm3_finish (void* ctx, SM3_DIGEST output)
{
	int ret = 0;
	uint8_t *buffer = NULL;
	sm3_finish_req_st *req = NULL;
	sm3_finish_rsp_st *rsp = NULL;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	void *vaddr = NULL;
	tcs_sm3_context_st *cntx = (tcs_sm3_context_st*)ctx;
	
	if (NULL == (buffer = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	req = (sm3_finish_req_st*)buffer;
	rsp = (sm3_finish_rsp_st*)(buffer + CMD_DEFAULT_ALLOC_SIZE/2);

	httc_util_pr_dev ("cntx->datalen: %d\n", cntx->datalen);

	if (cntx->datalen){
		if (0 == (vaddr = httc_kmalloc (cntx->datalen, GFP_KERNEL))){
			httc_util_pr_error ("vaddr Alloc hter!\n");
			ret = TSS_ERR_NOMEM;
			goto out;
		}
		if (cntx->datalen)	memcpy ((char *)vaddr, cntx->data, cntx->datalen);
		//httc_util_dump_hex ("vaddr", vaddr, 16);
		httc_util_pr_dev ("cntx->datalen: 0x%x!\n", cntx->datalen);
		tpcm_util_cache_flush ((char *)vaddr, cntx->datalen);
		tpcm_memcpy_u64 (&req->seg.address, htonll (tdd_get_phys_addr((void*)vaddr)));
	}
	
	tpcm_memcpy_u32 (&req->seg.length, htonl (cntx->datalen));
		
	req->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	req->uiCmdLength = htonl (sizeof (sm3_finish_req_st));
	req->uiCmdCode = htonl (TPCM_ORD_SM3_FINISH);
	req->ctx_len = htonl (sizeof (SM3_CONTEXT));
	tpcm_memcpy ((void*)req->ctx, cntx->context, sizeof (SM3_CONTEXT));
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (req, sizeof (sm3_finish_req_st), rsp, &rspLen))) goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if ((ret = tpcmRspRetCode (rsp))) goto out;
	
	if(tpcmReqLength(rsp) != sizeof(sm3_finish_rsp_st)){
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(sm3_finish_rsp_st), tpcmReqLength(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	
	tpcm_memcpy(output, rsp->hash, DEFAULT_HASH_SIZE);
out:
	if (vaddr) httc_kfree (vaddr);
	if (buffer) tdd_free_data_buffer (buffer);
	if (ctx) httc_kfree (ctx);
	return ret;	
}
EXPORT_SYMBOL (tcsk_sm3_finish);

