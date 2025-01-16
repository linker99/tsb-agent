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
#include "./expend/tcsk_sm.h"

uint8_t** tcs_util_get_tcs_mmap_addr_list (void);
int tcs_util_get_tcs_mmap_addr_num (void);
int tcs_util_get_tcs_mmap_seg_limit (void);

#define SEG_LIMIT_SIZE (64*1024)
typedef unsigned char SM3_CONTEXT[512];

#pragma pack(push, 1)

typedef struct{
	uint64_t address;	/** Physical Address */
	uint32_t length;
}addr_seg_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t size;
}sm3_req_user_st;

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
	COMMAND_HEADER;
	uint32_t ctx_len;
	SM3_CONTEXT ctx;
	uint32_t size;
}sm3_update_req_user_st;

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
	SM3_CONTEXT context;
	int datalen;
	uint8_t data[SEG_LIMIT_SIZE];
} tcs_sm3_context_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t ctx_len;
	tcs_sm3_context_st ctx;
}sm3_finish_req_user_st;

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

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t iv[SM4_IV_SIZE];
	uint32_t size;
}sm4_encrypt_req_user_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t iv[SM4_IV_SIZE];
	uint32_t size;
	uint32_t addr_num;
	uint32_t addr_limit;
	uint64_t phys_addr[0];
}sm4_encrypt_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t size;
}sm4_encrypt_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t iv[SM4_IV_SIZE];
	uint32_t size;
}sm4_decrypt_req_user_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t mode;
	uint8_t  key[SM4_KEY_SIZE];
	uint8_t iv[SM4_IV_SIZE];
	uint32_t size;
	uint32_t addr_num;
	uint32_t addr_limit;
	uint64_t phys_addr[0];
}sm4_decrypt_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t size;
}sm4_decrypt_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t  privkey[SM2_PRIVATE_KEY_SIZE];
	uint8_t  pubkey[SM2_PUBLIC_KEY_SIZE];
	uint32_t size;
}sm2_sign_req_user_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t  privkey[SM2_PRIVATE_KEY_SIZE];
	uint8_t  pubkey[SM2_PUBLIC_KEY_SIZE];
	uint32_t size;
	uint32_t addr_num;
	uint32_t addr_limit;
	uint64_t phys_addr[0];
}sm2_sign_req_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t  pubkey[SM2_PUBLIC_KEY_SIZE];
	uint8_t  sig[DEFAULT_SIGNATURE_SIZE];
	uint32_t size;
	uint32_t addr_num;
	uint32_t addr_limit;
	uint64_t phys_addr[0];
}sm2_verify_req_user_st;

typedef struct{
	COMMAND_HEADER;
	uint8_t  pubkey[SM2_PUBLIC_KEY_SIZE];
	uint8_t  sig[DEFAULT_SIGNATURE_SIZE];
	uint32_t size;
	uint32_t addr_num;
	uint32_t addr_limit;
	uint64_t phys_addr[0];
}sm2_verify_req_st;

#pragma pack(pop)

//#define RATE_CHECK

int tpcm_ioctl_sm3 (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm3_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm3_req_user_st *)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm3_req_st) + seg_num * sizeof (addr_seg_st);
	uint64_t trans = 0;

	addr_seg_st *virt_seg = NULL;
	unsigned int munit_size = sizeof (addr_seg_st) * seg_num;
		
#ifdef RATE_CHECK
	struct timeval start;
	struct timeval end;
	int in_sec;		/* Seconds. */
	int in_usec;	/* Microseconds. */
#endif

	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (cmd = (sm3_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (virt_seg = (addr_seg_st *)httc_vmalloc (munit_size))){
		printk ("[%s:%d] Malloc virmunit hter\n", __func__, __LINE__);
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}
	
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		cmd->seg[i].length = htonl(seg_size);
		tpcm_memcpy(&(cmd->seg[i].address), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SM3);
	cmd->seg_num = htonl (seg_num);
	
#ifdef RATE_CHECK
	httc_gettimeofday (&start);
	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);
	httc_gettimeofday (&end);
	in_sec = (end.tv_usec - start.tv_usec >= 0) ? (end.tv_sec - start.tv_sec) : (end.tv_sec - start.tv_sec - 1);
	in_usec = (end.tv_usec - start.tv_usec >= 0) ? (end.tv_usec - start.tv_usec) : (end.tv_usec - start.tv_usec + 1000000);

	if (size / 1024 / 1024){
		printk (">>> size(%d.%03dMB), time(%d.%06ds) <<<\n",
				size / 1024 / 1024, size / 1024 % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else if (size / 1024){
		printk (">>> size(%d.%03dKB), time(%d.%06ds) <<<\n",
				size / 1024, size % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else{
		printk (">>> size(%dB), time(%d.%06ds) <<<\n", size, in_sec, in_usec);
	}
#else
  
	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);
  
#endif


	if(virt_seg) httc_vfree(virt_seg);
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

int tpcm_ioctl_sm3_update (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm3_update_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm3_update_req_user_st *)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm3_update_req_st) + seg_num * sizeof (addr_seg_st);
	uint64_t trans = 0;

	addr_seg_st *virt_seg = NULL;
	unsigned int munit_size = sizeof (addr_seg_st) * seg_num;
		
#ifdef RATE_CHECK
	struct timeval start;
	struct timeval end;
	int in_sec;		/* Seconds. */
	int in_usec;	/* Microseconds. */
#endif

	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (cmd = (sm3_update_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (virt_seg = (addr_seg_st *)httc_vmalloc (munit_size))){
		printk ("[%s:%d] Malloc virmunit hter\n", __func__, __LINE__);
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}
	
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		cmd->seg[i].length = htonl(seg_size);
		tpcm_memcpy(&(cmd->seg[i].address), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SM3_UPDATE);
	cmd->ctx_len = htonl (sizeof (SM3_CONTEXT));
	tpcm_memcpy (cmd->ctx, ((sm3_update_req_user_st*)ucmd)->ctx, ((sm3_update_req_user_st*)ucmd)->ctx_len);
	cmd->seg_num = htonl (seg_num);
	
#ifdef RATE_CHECK
	httc_gettimeofday (&start);
	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);
	httc_gettimeofday (&end);
	in_sec = (end.tv_usec - start.tv_usec >= 0) ? (end.tv_sec - start.tv_sec) : (end.tv_sec - start.tv_sec - 1);
	in_usec = (end.tv_usec - start.tv_usec >= 0) ? (end.tv_usec - start.tv_usec) : (end.tv_usec - start.tv_usec + 1000000);

	if (size / 1024 / 1024){
		printk (">>> size(%d.%03dMB), time(%d.%06ds) <<<\n",
				size / 1024 / 1024, size / 1024 % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else if (size / 1024){
		printk (">>> size(%d.%03dKB), time(%d.%06ds) <<<\n",
				size / 1024, size % 1024 * 1000 / 1024 , in_sec, in_usec);
	}else{
		printk (">>> size(%dB), time(%d.%06ds) <<<\n", size, in_sec, in_usec);
	}
#else
	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);
#endif


	if(virt_seg) httc_vfree(virt_seg);
	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

int tpcm_ioctl_sm3_finish (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int ret = 0;
	sm3_finish_req_st *req = NULL;
	void *vaddr = NULL;
	tcs_sm3_context_st *cntx = &((sm3_finish_req_user_st*)ucmd)->ctx;
	
	if (NULL == (req = (sm3_finish_req_st*)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

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
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (req, sizeof (sm3_finish_req_st), rsp, rspLen))) goto out;
	
out:
	if (vaddr) httc_kfree (vaddr);
	if (req) tdd_free_data_buffer (req);

	return ret;	
}
int tpcm_ioctl_sm4_encrypt (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm4_encrypt_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm4_encrypt_req_user_st*)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm4_encrypt_req_st) + seg_num * sizeof (uint64_t);
	uint64_t trans = 0;

#ifdef __aarch64__
	int enc_size = 0;
#endif

	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (cmd = (sm4_encrypt_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		tpcm_memcpy(&(cmd->phys_addr[i]), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (((sm4_encrypt_req_user_st*)ucmd)->uiCmdTag);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (((sm4_encrypt_req_user_st*)ucmd)->uiCmdCode);
	cmd->mode = htonl(((sm4_encrypt_req_user_st*)ucmd)->mode);
	tpcm_memcpy (cmd->key, ((sm4_encrypt_req_user_st*)ucmd)->key, SM4_KEY_SIZE);
	tpcm_memcpy (cmd->iv, ((sm4_encrypt_req_user_st*)ucmd)->iv, SM4_IV_SIZE);
	cmd->size = htonl (size);
	cmd->addr_num = htonl (seg_num);
	cmd->addr_limit = htonl (seg_limit);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

#ifdef __aarch64__	
	if ((0 == tpcmRspRetCode (rsp)) && (0 != (enc_size = ntohl (((sm4_encrypt_rsp_st*)rsp)->size)))){
		for (i = 0; i < seg_num; i++){
			seg_size = (enc_size < seg_limit) ? enc_size : seg_limit;
			httc_arch_invalidate_pmem (data_addr[i], seg_size);
			enc_size -= seg_size;
		}
	}
#endif 

	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

int tpcm_ioctl_sm4_decrypt (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm4_decrypt_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm4_decrypt_req_user_st*)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm4_decrypt_req_st) + seg_num * sizeof (uint64_t);
	uint64_t trans = 0;

#ifdef __aarch64__
	int dec_size = 0;
#endif
	
	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	 
	if (NULL == (cmd = (sm4_decrypt_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		tpcm_memcpy(&(cmd->phys_addr[i]), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (((sm4_decrypt_req_user_st*)ucmd)->uiCmdTag);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (((sm4_decrypt_req_user_st*)ucmd)->uiCmdCode);
	cmd->mode = htonl (((sm4_decrypt_req_user_st*)ucmd)->mode);
	tpcm_memcpy (cmd->key, ((sm4_decrypt_req_user_st*)ucmd)->key, SM4_KEY_SIZE);
	tpcm_memcpy (cmd->iv, ((sm4_decrypt_req_user_st*)ucmd)->iv, SM4_IV_SIZE);
	cmd->size = htonl (size);
	cmd->addr_num = htonl (seg_num);
	cmd->addr_limit = htonl (seg_limit);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);
#ifdef __aarch64__
	if ((0 == tpcmRspRetCode (rsp)) && (0 != (dec_size = ntohl (((sm4_decrypt_rsp_st*)rsp)->size)))){
		for (i = 0; i < seg_num; i++){
			seg_size = (dec_size < seg_limit) ? dec_size : seg_limit;
			httc_arch_invalidate_pmem (data_addr[i], seg_size);
			dec_size -= seg_size;
		}
	}
#endif 

	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
}

int tpcm_ioctl_sm2_sign_e (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm2_sign_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm2_sign_req_user_st *)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm2_sign_req_st) + seg_num * sizeof (uint64_t);
	uint64_t trans = 0;
	
	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	if (NULL == (cmd = (sm2_sign_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		tpcm_memcpy(&(cmd->phys_addr[i]), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SM2SignE);
	tpcm_memcpy (cmd->privkey, ((sm2_sign_req_user_st*)ucmd)->privkey, SM2_PRIVATE_KEY_SIZE);
	tpcm_memcpy (cmd->pubkey, ((sm2_sign_req_user_st*)ucmd)->pubkey, SM2_PUBLIC_KEY_SIZE);
	cmd->size = htonl (size);
	cmd->addr_num = htonl (seg_num);
	cmd->addr_limit = htonl (seg_limit);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

	if (cmd) tdd_free_data_buffer (cmd);
	return ret;	
	
}

int tpcm_ioctl_sm2_verify_e (void *ucmd, int ucmdLen, void *rsp, int *rspLen)
{	
	int i = 0;
	int ret = 0;
	void **data_addr = NULL;
	sm2_verify_req_st *cmd = NULL;
	int seg_size = 0;
	int size = ((sm2_verify_req_user_st *)ucmd)->size;
	int left_size = size;
	int seg_num = tcs_util_get_tcs_mmap_addr_num ();
	int seg_limit = tcs_util_get_tcs_mmap_seg_limit ();
	int cmdLen = sizeof (sm2_verify_req_st) + seg_num * sizeof (uint64_t);
	uint64_t trans = 0;
	
	if (NULL == (data_addr = (void**)tcs_util_get_tcs_mmap_addr_list())){
		printk ("[%s:%d] tddl_get_mmap_virt_addr hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	 
	if (NULL == (cmd = (sm2_verify_req_st *)tdd_alloc_data_buffer (cmdLen))){
		printk ("[%s:%d] get_file_integrity_req_st alloc hter!\n", __func__, __LINE__);
		return TSS_ERR_NOMEM;
	}
	for (i = 0; i < seg_num; i++){
		seg_size = (left_size < seg_limit) ? left_size : seg_limit;
		trans = htonll (tdd_get_phys_addr(data_addr[i]));
		tpcm_memcpy(&(cmd->phys_addr[i]), &trans, sizeof(uint64_t));
		tpcm_util_cache_flush (data_addr[i], seg_size);
		left_size -= seg_size;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SM2VerifyE);
	tpcm_memcpy (cmd->pubkey, ((sm2_verify_req_user_st*)ucmd)->pubkey, SM2_PUBLIC_KEY_SIZE);
	tpcm_memcpy (cmd->sig, ((sm2_verify_req_user_st*)ucmd)->sig, DEFAULT_SIGNATURE_SIZE);
	cmd->size = htonl (size);
	cmd->addr_num = htonl (seg_num);
	cmd->addr_limit = htonl (seg_limit);

	ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, rspLen);

	if (cmd) tdd_free_data_buffer (cmd);
	return ret;		
}

