#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>

#include "sys.h"
#include "mem.h"
#include "sem.h"
#include "file.h"
#include "debug.h"
#include "convert.h"

#include "tcs.h"
#include "tcs_error.h"
#include "tcs_auth.h"
#include "tcs_util_policy_update.h"
#include "tpcm_command.h"
#include "transmit.h"
#include "crypto/sm/sm2_if.h"
#include "crypto/sm/sm3.h"

#include "tcs_tpcm_error.h"
#include "tcs_attest.h"
#include "convert.h"
#include "debug.h"

#ifndef NO_TSB
#include <tsbapi/tsb_measure_user.h>
#endif

#pragma pack(push, 1)
typedef struct tcs_req_inform_update{
	COMMAND_HEADER;
	unsigned int ord;
	int size;
	int num;
	uint8_t policy[0];
}tcs_req_inform_update_st;
#pragma pack(pop)



int tcs_util_parse_file_protect (uint8_t *policy, struct file_protect_item **items, int *num, int *length);
int tcs_util_parse_process_identity (uint8_t *policy, struct process_identity **ids,int *num,int *length);
int tcs_util_parse_process_role (uint8_t *policy, struct process_role **roles,int *num,int *length);
int tcs_util_parse_ptrace_protect (uint8_t *policy, struct process_role **roles,int *num,int *length);

int tcs_util_read_replay_counter (uint64_t *replay_counter)
{
	int r = 0;
	void *rdata = NULL;
	unsigned long rlen = 0;

	if ((r = tcs_util_sem_get (TCS_SEM_INDEX_POLICY)))	return r;

	if (access (TCS_POLICY_REPLAY_PATH, R_OK)){
		replay_counter = 0;
	}else{
		rdata = httc_util_file_read_full (TCS_POLICY_REPLAY_PATH, &rlen);
		if (!rdata){
			tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
			httc_util_pr_error ("Read replay counter error!\n");
			return TSS_ERR_READ;
		}
		if (rlen != sizeof (uint64_t) + sizeof (int) * 2){/** size + num + replay */
			tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
			httc_free (rdata);
			return TSS_ERR_BAD_DATA;
		}
		*replay_counter = *((uint64_t*)(rdata + sizeof (int) * 2));
		httc_free (rdata);
	}

	tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
	return TSS_SUCCESS;
}

/** 修改本地防重放计数 */

int tcs_util_write_replay_counter (uint64_t counter)
{	
	int r;
	FILE *fp = NULL;
	int num = 1;
	int size = sizeof (uint64_t);
	void *rdata = NULL;
	unsigned long rlen = 0;
	uint64_t local_replay = 0;
	uint64_t tpcm_replay = 0;

	if((r = tcs_get_replay_counter (&tpcm_replay))) {
		httc_util_pr_error("[tcs_get_replay_counter] r: 0x%08x\n", r);
		return r;
	}
	httc_util_pr_dev ("tpcm_replay: %llu(0x%llx)\n", (unsigned long long)tpcm_replay, (unsigned long long)tpcm_replay);

	if ((r = tcs_util_sem_get (TCS_SEM_INDEX_POLICY)))	return r;

	if (access (TCS_POLICY_REPLAY_PATH, R_OK)){
		local_replay = 0;
	}else{
		rdata = httc_util_file_read_full (TCS_POLICY_REPLAY_PATH, &rlen);
		if (!rdata){
			tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
			httc_util_pr_error ("Read replay counter error!\n");
			return TSS_ERR_READ;
		}
		
		if (rlen != sizeof (uint64_t) + sizeof (int) * 2){/** size + num + replay */
			tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
			httc_free (rdata);
			return TSS_ERR_BAD_DATA;
		}
		local_replay = *((uint64_t*)(rdata + sizeof (int) * 2));
		httc_free (rdata);
	}
	httc_util_pr_dev ("cur_replay: %llu(0x%llx)\n", (unsigned long long)local_replay, (unsigned long long)local_replay);

	counter = counter & 0x7FFFFFFFFFFFFFFF;
	if (counter <= MAX (tpcm_replay, local_replay)){
		httc_util_pr_error ("Invalid replay counter (%llu <= %llu)\n", (unsigned long long)counter, (unsigned long long)MAX (tpcm_replay, local_replay));
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_VERIFY_REPLAY;
	}

	/** д����ʱ�����ļ� */
	if(NULL == (fp = fopen (TCS_POLICY_REPLAY_PATH, "w"))) {
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_FILE;
	}
	/** Write size */
	if (sizeof(int) != fwrite (&size, sizeof(char), sizeof(int), fp)){
		fclose(fp);
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_WRITE;
	}
	/** Write num */
	if (sizeof(int) != fwrite (&num, sizeof(char), sizeof(int), fp)){
		fclose(fp);
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_WRITE;
	}
	/** Write policy */
	if (size != fwrite(&counter, sizeof(char), size, fp)){
		fclose(fp);
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_WRITE;
	}
	fclose(fp);
	tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
	return TSS_SUCCESS;
}

/** 从本地获取策略版本 */
int tcs_util_read_policies_version (struct policy_version *version, int *num_inout)
{
	int r=0;
	int policy_size = 0;
	int policy_num = 0;
	void *rdata = NULL;
	
	r = tcs_util_read_policy (TCS_POLICY_VERSION_PATH, &rdata, &policy_size, &policy_num);
	if (r) return r;
	//version = (struct policy_version *)rdata;
 	//httc_util_pr_info ("policy_size:%d\n",policy_size);
	//httc_util_dump_hex("rdata", rdata, policy_size);
	if (rdata) {
		memcpy(version,rdata,policy_size);
		*num_inout=policy_num;
		httc_free (rdata);
	}else{
		return TSS_ERR_ITEM_NOT_FOUND;
	}
 	//httc_util_pr_info ("*num_inout:%d\n",*num_inout);
	return r;
}

/** 从本地写入策略版本 */
int tcs_util_write_policy_version (unsigned int id, uint64_t version)
{

	int r,i=0,flag=0;
	int policy_size = 0;
	int policy_num = 0,be_policy=0;
  void *rdata = NULL;
	struct policy_version *policies=NULL;
	r = tcs_util_read_policy (TCS_POLICY_VERSION_PATH, (void **)&rdata, &policy_size, &policy_num);
	if (r) return r;
  
	policies = (struct policy_version *)rdata;
//httc_util_dump_hex("rdata", rdata, policy_size);
//httc_util_dump_hex("policies", policies, policy_size);
	for(i=0;i<policy_num;i++)
	{

  be_policy=ntohl(policies[i].be_policy);
  
	if(be_policy==id)
	{
	policies[i].be_version=htonll(version);
	flag=1;
	}

	}

	if(flag==0)/*δ�ҵ�*/
	{
		httc_util_pr_error("not found command:%u version:%llu",id,(unsigned long long)version);
		r=TSS_ERR_INVALID_POLICY;
		goto out;
	}

	r=tcs_util_write_policy (TCS_POLICY_VERSION_PATH,policies, policy_size, policy_num);
	
out:
	if (rdata)
	{
		free(rdata);
	}
	return r;
}

/** 读取管理员证书列表，根据uid返回管理员证书*/
int tcs_util_get_cert_by_uid (const char *uid, struct admin_cert_item *cert)
{
	int i,r;
	struct admin_cert_item *policy = NULL;
	int policy_num = 0;

	if ((r = tcs_get_admin_list (&policy, &policy_num))){
		httc_util_pr_error ("tcs_get_admin_list error: 0x%x\n", r);
		return r;
	}
	if (! policy || !policy_num){
		return TSS_ERR_ITEM_NOT_FOUND;
	}

	if (!uid){
		memcpy (cert, policy, sizeof(struct admin_cert_item));
		free (policy);
		return 0;
	}
	for (i = 0; i < policy_num; i++){
		if (!strncmp ((const char *)policy[i].name, uid, strlen(uid)<TPCM_UID_MAX_LENGTH ? strlen(uid) : TPCM_UID_MAX_LENGTH)){
			memcpy (cert, &policy[i], sizeof(struct admin_cert_item));
			free (policy);
			return 0;
		}
	}
	if (policy) free (policy);
	return TSS_ERR_INVALID_UID;
}

/** 本地pik私钥数据签名 */
int tcs_util_pik_sign (const char *data, int datalen, char sign[DEFAULT_SIGNATURE_SIZE])
{
	int r = 0;
	uint8_t *sig = NULL;
	uint32_t siglen = 0;
	int pub_len = SM2_PUBLIC_KEY_SIZE;
	uint8_t pub[SM2_PUBLIC_KEY_SIZE] = {0};
	uint8_t priv[SM2_PRIVATE_KEY_SIZE] = {0};

	if ((r = tcs_util_get_pik_privkey (priv))){
		httc_util_pr_error ("get_pik_privkey error: %d(0x%x)\n", r, r);
		return r;
	}
	if ((r = tcs_get_pik_pubkey (pub, &pub_len))){
		httc_util_pr_error ("get_pik_pubkey error: %d(0x%x)\n", r, r);
		return r;
	}
	if ((r = os_sm2_sign ((const unsigned char *)data, datalen, priv, SM2_PRIVATE_KEY_SIZE, pub, pub_len, &sig, &siglen))){
		httc_util_pr_error ("os_sm2_sign error: %d(0x%x)\n", r, r);
		return r;
	}
	if (sig) memcpy (sign, sig, siglen);
	free (sig);
	return 0;
}

/**纯软件版本证书验签 */
int tcs_util_verify_update (struct admin_cert_item *cert,
		int auth_type, int auth_length, unsigned char *auth, void *update, int update_size)
{
	int r;
	r = os_sm2_verify (update, update_size, cert->data, ntohl(cert->be_cert_len), auth, auth_length);
	return r ? TSS_ERR_VERIFY : TSS_SUCCESS;
}

/** 本地写策略 */
int tcs_util_write_policy (const char* path, void *policy, int size, int num)
{
	int r;
	int ret;
	FILE *fp = NULL;

	char *tmp_path = NULL;
	int tmp_path_len = 0;
	struct timeval time;
	uint64_t usec = 0;

	//httc_util_pr_dev ("size: %d, num: %d, path: %s\n", size, num, path);
	//httc_util_dump_hex ("policy", policy, size);
	
	gettimeofday (&time, NULL);
	usec = time.tv_sec * 1000000 + time.tv_usec;

	tmp_path_len = strlen (path) + 64;
	if (NULL == (tmp_path = httc_malloc (tmp_path_len))){
		httc_util_pr_error ("Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	snprintf (tmp_path, tmp_path_len, "%s.%llu", path, (unsigned long long)usec);

	/** д����ʱ�����ļ� */
	if(NULL == (fp = fopen (tmp_path, "w"))) {
		httc_free (tmp_path);
		return TSS_ERR_FILE;
	}
	/** Write size */
	if (sizeof(int) != fwrite (&size, sizeof(char), sizeof(int), fp)){
		fclose(fp);
		httc_free (tmp_path);
		return TSS_ERR_WRITE;
	}
	/** Write num */
	if (sizeof(int) != fwrite (&num, sizeof(char), sizeof(int), fp)){
		fclose(fp);
		httc_free (tmp_path);
		return TSS_ERR_WRITE;
	}
	/** Write policy */
	if (size){
		if (size != fwrite(policy, sizeof(char), size, fp)){
			fclose(fp);
			httc_free (tmp_path);
			return TSS_ERR_WRITE;
		}
	}
	fclose(fp);

	/** ��������ʱ�����ļ� */
	if ((r = tcs_util_sem_get (TCS_SEM_INDEX_POLICY)))	return r;
	ret = rename (tmp_path, path);
	if(ret != 0){
		httc_util_pr_error("rename error\n");
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		httc_free (tmp_path);
		return TSS_ERR_FILE;
	}
	tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
	httc_free (tmp_path);
	return TSS_SUCCESS;
}

/** 本地读策略 */
int tcs_util_read_policy (const char* path, void **policy, int *size, int *num)
{
	int r;
	void *rdata = NULL;
	unsigned long rlen = 0;
	
	if ((r = tcs_util_sem_get (TCS_SEM_INDEX_POLICY)))	return r;

	if (access (path, F_OK)){
		*policy = NULL;
		*size = 0;
		*num = 0;
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		//httc_util_pr_dev ("*size: %d, *num: %d, path: %s\n", *size, *num, path);
		return TSS_SUCCESS;
	}

	rdata = httc_util_file_read_full (path, &rlen);
	if (!rdata){
		tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
		return TSS_ERR_READ;
	}
	tcs_util_sem_release (TCS_SEM_INDEX_POLICY);
	
	*size = *((int*)rdata);
	*num = *((int*)(rdata+sizeof(int)));
	if (*size != (rlen - sizeof (int) * 2)){
		httc_util_pr_dev ("Invalid policy!\n");
		if(rdata)
		{
			httc_free(rdata);
		}
		return TSS_ERR_BAD_DATA;
	}
	
	if (NULL == (*policy = malloc (*size))){
		httc_util_pr_error ("Policy Alloc error!\n");
		if(rdata)
		{
			httc_free(rdata);
		}
		return TSS_ERR_NOMEM;
	}
	memcpy (*policy, rdata + sizeof (int) * 2, rlen - sizeof (int) * 2);

	//httc_util_pr_dev ("*size: %d, *num: %d, path: %s\n", *size, *num, path);
	//httc_util_dump_hex ("*policy", *policy, *size);
	if(rdata)
	{
		httc_free(rdata);
	}
	return TSS_SUCCESS;
}

int tcs_util_get_pik_privkey (unsigned char priv[SM2_PRIVATE_KEY_SIZE])
{
	int ret=0;
	int size=0;
	int num=0;
	struct tcs_pik_para *key=NULL;
	if ((ret = tcs_util_read_policy (TCS_PIK_PATH, (void **)&key, &size, &num)))	return ret;
 
 if(size!=(SM2_PRIVATE_KEY_SIZE+SM2_PUBLIC_KEY_SIZE))
 {
 httc_util_pr_error("error,be_size:%d or key->priv_key is null\r\n", size);
 return ret;
 }
 memcpy(priv,key->priv_key,SM2_PRIVATE_KEY_SIZE);
 httc_util_dump_hex("pri", priv, SM2_PRIVATE_KEY_SIZE);
	return 0;
}

int tcs_util_inform_kernel_of_update (unsigned int command, void *policy, int size, int num)
{
	int r;
	int reqlen = sizeof (struct tcs_req_inform_update) + size;
	int rsplen = sizeof (tpcm_rsp_header_st);
	struct tcs_req_inform_update *req = NULL;
	tpcm_rsp_header_st rsp;

	if(NULL == (req = httc_malloc(reqlen))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	req->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	req->uiCmdLength = reqlen;
	req->uiCmdCode = TSS_ORD_InformPolicy;
	req->ord = command;
	req->size = size;
	req->num = num;
	if(size)memcpy (req->policy, policy, size);

	if (!(r = tpcm_transmit (req, reqlen, &rsp, &rsplen))){
		r = tpcmLocalRspCmd (&rsp);
	}
	if(req) httc_free(req);

	return r;
}

#define POLICY_MAX_NUM 8
#define CERT_TYPE_MAX 4

enum
{
	POLICY_SPECIFIC_LIBS_YES = 0,
	POLICY_SPECIFIC_LIBS_NO,
	POLICY_SPECIFIC_LIBS_ALL
};
enum
{
	CONTROL_NO = 0, //不控�?
	CONTROL_OK,		//控制
	CONTROL_MAX,	// 错�??�?
};
#define DMEASURE_CONFIG_DELAY 60


uint32_t check_tpcm_id_func(unsigned char *tpcmid, uint32_t len)
{
	uint32_t rc = 0;
	uint8_t id[128] = {0};
	int id_len = sizeof(id);
	rc = tcs_get_tpcm_id(id, &id_len);
	if (rc)
	{
		httc_util_pr_dev("[tcs_get_tpcm_id] ret: 0x%08x\n", rc);
		return 1;
	}
	rc = memcmp(tpcmid, id, len);
	if (rc != 0)
	{
		httc_util_pr_error("check tpcm id error \r\n");
		httc_util_pr_error("tpcm except: \r\n");
		httc_util_dump_hex("id",id, 32);
		httc_util_pr_error("tpcm actual: \r\n");
		httc_util_dump_hex("tpcmid",tpcmid, 32);
	}

	return rc;
}

int tcs_util_check_admin_cert_update(struct admin_cert_update *update)
{
	uint32_t rc = 0;
	uint64_t counter;
	
	if (update == NULL)
	{
		httc_util_pr_error("parameter is NULL\n");
		rc = TSS_ERR_PARAMETER;
		return rc;
	}
	
	do
	{

	

		if (ntohl(update->be_size) != sizeof(struct admin_cert_update) )
		{
			httc_util_pr_error("error,be_size:%d\r\n", ntohl(update->be_size));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		
		if ((ntohl(update->be_action) != POLICY_ACTION_SET) || (ntohl(update->be_action) != POLICY_ACTION_ADD) || (ntohl(update->be_action) != POLICY_ACTION_DELETE) || (ntohl(update->be_action) != POLICY_ACTION_MODIFY))
		{
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)update->be_replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}

		
		if ( ntohl(update->cert.be_cert_len) > MAX_CERT_SIZE)
		{
			httc_util_pr_error("cert length[0x%x] is more than MAX_CERT_SIZE[0x%x]\n",  ntohl(update->cert.be_cert_len), MAX_CERT_SIZE);
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	
		if (ntohl(update->cert.be_cert_type) >= CERT_TYPE_MAX)
		{
			httc_util_pr_error("be_cert_type[0x%x] is more than 0x%x\n", ntohl(update->cert.be_cert_type), CERT_TYPE_MAX - 1);
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	} while (0);

	return 0;
}

int tcs_util_check_admin_auth_policy_update(struct admin_auth_policy_update *update)
{
	uint32_t i = 0;
	uint32_t rc = 0;
	struct admin_auth_policy item;
	uint32_t policy_object_id = 0;
	uint32_t policy_auth_type = 0;
	uint64_t replay_counter=0;
	if (update == NULL)
	{
		httc_util_pr_error("tcs_util_check_admin_auth_policy_update parameter is NULL\n");
		rc = TSS_ERR_PARAMETER;
		return rc;
	}
	do
	{


		if (ntohl(update->be_number) > POLICY_MAX_NUM)
		{
			httc_util_pr_error("update->be_number is %d over MAX:%d \r\n",  ntohl(update->be_number), POLICY_MAX_NUM);
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

	

		if (ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("action is update->be_action:%d is llegal \r\n", ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}
		if (check_tpcm_id_func(update->tpcm_id, 32) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		for (i = 0; i < ntohl(update->be_number); i++)
		{

			item = update->policies[i];

			policy_object_id = item.be_object_id;
			policy_object_id = ntohl(policy_object_id);

			if (policy_object_id >= TPCM_ADMIN_AUTH_POLICY_MAX || (policy_object_id < TPCM_ADMIN_AUTH_POLICY_BOOT_REF))
			{
				httc_util_pr_error("policy_object_id[%d] >= %d\r\n", policy_object_id, TPCM_ADMIN_AUTH_POLICY_MAX);
				rc = TSS_ERR_INVALID_POLICY;
				break;
			}
			policy_auth_type = item.be_admin_auth_type;
			policy_auth_type = ntohl(policy_auth_type);
			if (policy_auth_type > ADMIN_AUTH_POLICY_AND_CERT)
			{
				httc_util_pr_error("policy_auth_type[%d] > %d \r\n", policy_auth_type, ADMIN_AUTH_POLICY_AND_CERT);
				rc = TSS_ERR_BAD_DATA;
				break;
			}
		}

	} while (0);

	return rc;
}

#define BASE_LIB_NUM_MAX 25
static uint32_t get_boot_ref_item_size(struct boot_ref_item *item)
{
	uint32_t item_size = 0;

	if (NULL == item)
	{
		httc_util_pr_error("para NULL\n");
		return (0);
	}

	item_size += sizeof(struct boot_ref_item);

	item_size += ntohs(item->be_hash_number) * ntohs(item->be_hash_length);
	item_size += ntohs(item->be_name_length) + ntohs(item->be_extend_size);

	return HTTC_ALIGN_SIZE(item_size, 4);
}
static uint32_t get_boot_ref_size(const uint8_t *buffer, uint32_t number)
{
	uint32_t i = 0;
	uint32_t offset = 0;
	struct boot_ref_item *item = NULL;

	for (i = 0; i < number; ++i)
	{
		item = (struct boot_ref_item *)(buffer + offset);
		offset += get_boot_ref_item_size(item);
	}

	return offset;
}
int tcs_util_check_boot_references_update(struct boot_references_update *update)
{
	uint32_t rc = TPCM_SUCCESS;
	 uint64_t replay_counter = 0;
	uint32_t boot_ref_data_size = 0;

	do
	{

		if (NULL == update)
		{
			httc_util_pr_error("para is NULL\n");
			rc = TSS_ERR_PARAMETER;
			break;
		}

	

		// check para
		if (ntohl(update->be_size) != sizeof(struct boot_references_update))
		{
			httc_util_pr_error("be_size[%lu] != %lu\n", (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct boot_references_update));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if ((!ntohl(update->be_item_number)) || (ntohl(update->be_item_number) > BASE_LIB_NUM_MAX))
		{
			httc_util_pr_error("be_item_number[%d]\n", ntohl(update->be_item_number));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		boot_ref_data_size = get_boot_ref_size(update->data, ntohl(update->be_item_number));
		if (boot_ref_data_size != ntohl(update->be_data_length))
		{

			httc_util_pr_error("para boot_data_size=%d,update->be_data_length = %d\n", boot_ref_data_size, ntohl(update->be_data_length));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	
		if (ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("error,action type[%d] is not exist\n", ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}

	} while (0);

	return rc;
}
int tcs_util_check_dmeasure_policy_update(struct dmeasure_policy_update *update)
{
	uint32_t rc = TPCM_SUCCESS;
uint64_t replay_counter=0;
	do
	{
		if (NULL == update)
		{
			httc_util_pr_error("para is NULL\n");
			rc = TSS_ERR_PARAMETER;
			break;
		}

		
		if ( ntohl(update->be_size) != sizeof(struct dmeasure_policy_update))
		{
			httc_util_pr_error("be_size[%lu] != [%lu]\n", (unsigned long )ntohl(update->be_size), (unsigned long )sizeof(struct dmeasure_policy_update));
			rc = TSS_ERR_BAD_DATA;

			break;
		}

		
		if ( ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("error,action type[%lu] is not exist\n",  (unsigned long )ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}
		replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		
		if (ntohl(update->be_item_number) > POLICY_MAX_NUM)
		{
			httc_util_pr_error("update->be_item_number is %d over MAX:%d", ntohl(update->be_item_number), POLICY_MAX_NUM);
			rc = TSS_ERR_PARAMETER;
			break;
		}
		//httc_util_pr_dev("item_num = %d\n", ntohl(update->be_item_number));
		
		//httc_util_pr_dev("be_size[%d], be_data_length[%d]\n",  ntohl(update->be_size), ntohl(update->be_data_length));

		uint32_t item_all_size = sizeof(struct dmeasure_policy_item) * ntohl(update->be_item_number);
		if ( ntohl(update->be_data_length) != item_all_size)
		{
			httc_util_pr_error("para dmeasure item_data_size=%d,update->be_data_length = %d\n", item_all_size,  ntohl(update->be_data_length));
			rc = TSS_ERR_PARAMETER;
			break;
		}

	} while (0);

	return rc;
}

int tcs_util_check_dmeasure_process_policy_update(struct dmeasure_process_policy_update *update)
{
	uint32_t rc = TPCM_SUCCESS;
	uint32_t i = 0;
	uint32_t actual_size = 0;
 uint32_t be_object_id_length = 0;
	uint64_t replay_counter=0;
	struct dmeasure_process_item *item = NULL;

	do
	{

		if (NULL == update)
		{
			httc_util_pr_error("input para is NULL\n");
			rc = TSS_ERR_PARAMETER;
			break;
		}

	
		if (ntohl(update->be_size) != sizeof(struct dmeasure_process_policy_update))
		{
			httc_util_pr_error("update->be_size[%lu] != [%lu]\n",(unsigned long ) ntohl(update->be_size), (unsigned long )sizeof(struct dmeasure_process_policy_update));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	

		if (ntohl(update->be_action) >= POLICY_ACTION_MODIFY)
		{
			httc_util_pr_error("update->be_action[%d]\n",ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

	

		for (i = 0; i < ntohl(update->be_item_number); i++)
		{

			item = (struct dmeasure_process_item *)(update->data + actual_size);
			be_object_id_length = ntohs(item->be_object_id_length);

			actual_size += HTTC_ALIGN_SIZE((sizeof(struct dmeasure_process_item) +be_object_id_length), 4);
		}

		if (ntohl(update->be_data_length) != actual_size)
		{
			httc_util_pr_error("para dmeasure process item_data_size=%d,update->be_data_length = %d\n", actual_size, ntohl(update->be_data_length));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
	} while (0);

	return rc;
}
uint32_t get_actual_item_size(struct file_integrity_item *item)
{
	uint32_t item_size = 0;
//httc_util_dump_hex("item", item, 128);
	if (NULL == item)
	{
		httc_util_pr_error("para NULL\n");
		return (0);
	}

	item_size += sizeof(struct file_integrity_item);
	item_size += item->extend_size;
	item_size += ntohs(item->be_path_length);
 	item_size+=32;
	//httc_util_pr_dev(" item_size:%d\r\n",item_size);
	return HTTC_ALIGN_SIZE(item_size, 4);
}

uint32_t get_actual_size_file(const uint8_t *buffer, uint32_t number)
{
	uint32_t i = 0;
	uint32_t offset = 0;
	struct file_integrity_item *item = NULL;

	for (i = 0; i < number; ++i)
	{
		item = (struct file_integrity_item *)(buffer + offset);
		offset += get_actual_item_size(item);
	}

	return offset;
}

int tcs_util_check_file_integrity_update(struct file_integrity_update *update)
{
	int32_t rc = 0;
	uint64_t replay_counter = 0;
	uint32_t actul_data_szie = 0;

	do
	{
		// check para
		if (ntohl(update->be_size) != sizeof(struct file_integrity_update))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("be_size[%lu] != [%lu]\n", (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct file_integrity_update));
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		
	//	httc_util_pr_dev("get_actual_size_file:number:%d be_data_length:%d\r\n", ntohl(update->be_item_number), ntohl(update->be_data_length));
		actul_data_szie = get_actual_size_file(update->data, ntohl(update->be_item_number));

		if (actul_data_szie !=ntohl(update->be_data_length))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("actul_data_szie[%d],update->be_data_length[%d]\n", actul_data_szie,ntohl(update->be_data_length));
			break;
		}

		if (ntohl(update->be_action) > POLICY_ACTION_MODIFY)
		{
			rc = TSS_ERR_INVALID_ACTION;
			httc_util_pr_error("be_action[%d] not support\n", ntohl(update->be_action));
			break;
		}
	} while (0);

	return (rc);
}

int tcs_util_check_critical_file_integrity_update(struct file_integrity_update *update)
{

	int32_t rc = 0;
	uint64_t replay_counter = 0;
	uint32_t actul_data_szie = 0;

	do
	{

		// check para
		if (ntohl(update->be_size) != sizeof(struct file_integrity_update))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("be_size[%lu] != [%lu]\n", (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct file_integrity_update));
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		actul_data_szie = get_actual_size_file(update->data, ntohl(update->be_item_number));
		if (actul_data_szie != ntohl(update->be_data_length))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("actul_data_szie[%d],update->be_data_length[%d]\n", actul_data_szie, ntohl(update->be_data_length));
			break;
		}

		if (ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			rc = TSS_ERR_INVALID_ACTION;
			httc_util_pr_error("be_action[%d] not support\n", ntohl(update->be_action));
			break;
		}
	} while (0);

	return (rc);
}

 uint32_t get_file_protect_date_len(uint8_t *items, uint32_t items_num)
{
	uint32_t date_len = 0;
	uint32_t i = 0;
	struct file_protect_item *items_tmp = NULL;
	//httc_util_pr_dev("items_num[%d]\n",items_num);
	for (i = 0; i < items_num; ++i)
	{
		items_tmp = (struct file_protect_item *)(items + date_len);
		httc_util_pr_dev("i[%d],be_privileged_process_num[%d]\n",i,items_tmp->be_privileged_process_num);
		date_len += sizeof(struct file_protect_item) + ntohs(items_tmp->be_privileged_process_num) * sizeof(struct file_protect_privileged_process);
	}

	return date_len;
}
int tcs_util_check_file_protect_update(struct file_protect_update *update)
{
	uint32_t rc = 0;
    uint32_t ref_total_len=0;
    uint64_t replay_counter = 0;

    
    do{
	  if (ntohl(update->be_size) != sizeof(struct file_protect_update))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("be_size[%lu] != [%lu]\n", (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct file_protect_update));
			break;
		}

	

	   replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n",(unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		ref_total_len = get_file_protect_date_len(update->data,ntohl(update->be_item_number));
		if (ref_total_len != ntohl(update->be_data_length))
		{
			rc = TSS_ERR_BAD_DATA;
			httc_util_pr_error("cal data_size[%d],update->be_data_length[%d]\n", ref_total_len, ntohl(update->be_data_length));
			break;
		}
    }while(0);
	return rc;
}


int tcs_util_check_global_control_policy_update(struct global_control_policy_update *update)
{
	uint32_t rc = 0;
uint64_t replay_counter=0;
	do
	{

		if (NULL == update)
		{
			httc_util_pr_error("input para is NULL\n");
			rc = TSS_ERR_PARAMETER;
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);
		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
	
		if ( ntohl(update->policy.be_size) != sizeof(struct global_control_policy))
		{
			httc_util_pr_error("be_size[%lu] != [%lu]\n",  (unsigned long)ntohl(update->policy.be_size), (unsigned long)sizeof(struct global_control_policy));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_boot_measure_on) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_boot_measure_on)[%d] != 0 or 1\n", ntohl(update->policy.be_boot_measure_on));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_program_measure_on) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_program_measure_on)[%d] != 0 or 1\n", ntohl(update->policy.be_program_measure_on));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_dynamic_measure_on) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_dynamic_measure_on)[%d] != 0 or 1\n", ntohl(update->policy.be_dynamic_measure_on));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_boot_control) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_boot_control)[%d] != 0 or 1\n", ntohl(update->policy.be_boot_control));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_program_control) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_program_control)[%d] != 0 or 1\n", ntohl(update->policy.be_program_control));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_program_measure_mode) > PROCESS_MEASURE_MODE_AUTO)
		{
			httc_util_pr_error("ntohl(update->policy.be_program_measure_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_program_measure_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_measure_use_cache) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_measure_use_cache)[%d] != 0 or 1\n", ntohl(update->policy.be_measure_use_cache));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_dmeasure_max_busy_delay) < DMEASURE_CONFIG_DELAY)
		{
			httc_util_pr_error("ntohl(update->policy.be_dmeasure_max_busy_delay)[%d] != 0 or 1\n", ntohl(update->policy.be_dmeasure_max_busy_delay));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_process_dmeasure_ref_mode) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_ref_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_ref_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_process_dmeasure_match_mode) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_match_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_match_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_process_dmeasure_lib_mode) > PROCESS_DMEASURE_MODE_NON_MEASURE || ntohl(update->policy.be_process_dmeasure_lib_mode) < PROCESS_DMEASURE_MODE_MEASURE)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_lib_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_lib_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_program_measure_match_mode) >= CONTROL_MAX)
		{
			httc_util_pr_error("ntohl(update->policy.be_program_measure_match_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_program_measure_match_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_process_verify_lib_mode) > PROCESS_VERIFY_MODE_SPECIFIC_LIB)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_verify_lib_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_verify_lib_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_process_dmeasure_sub_process_mode) > PROCESS_DMEASURE_MODE_NON_MEASURE || ntohl(update->policy.be_process_dmeasure_sub_process_mode) < PROCESS_DMEASURE_MODE_MEASURE)

		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_sub_process_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_sub_process_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		if (ntohl(update->policy.be_process_dmeasure_old_process_mode) > PROCESS_DMEASURE_MODE_NON_MEASURE || ntohl(update->policy.be_process_dmeasure_old_process_mode) < PROCESS_DMEASURE_MODE_MEASURE)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_old_process_mode)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_old_process_mode));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->policy.be_process_dmeasure_interval) == 0)
		{
			httc_util_pr_error("ntohl(update->policy.be_process_dmeasure_interval)[%d] != 0 or 1\n", ntohl(update->policy.be_process_dmeasure_interval));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	} while (0);

	return rc;
}
int tcs_util_check_process_identity_update(struct process_identity_update *update)
{
	uint32_t rc = 0;
	uint32_t i = 0;
	uint32_t item_len = 0;
	uint64_t replay_counter=0;
	struct process_identity identity_item;
	do
	{
		if ( ntohl(update->be_size) != sizeof(struct process_identity_update))
		{
			httc_util_pr_error("update->be_size[%lu] != [%lu]\n",  (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct process_identity_update));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
	

		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
	

		

		if (ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("be_action[%d] not support\n", ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		for (i = 0; i <ntohl(update->be_item_number); i++)
		{
			memcpy(&identity_item, update->data + item_len, sizeof(struct process_identity));
			if (identity_item.specific_libs >= POLICY_SPECIFIC_LIBS_ALL)
			{
				httc_util_pr_error("identity_item.specific_libs[%d] >= POLICY_SPECIFIC_LIBS_ALL[%d]\n",
								   identity_item.specific_libs, POLICY_SPECIFIC_LIBS_ALL);
				rc = TSS_ERR_BAD_DATA;
				break;
			}
			identity_item.be_hash_length = ntohs(identity_item.be_hash_length);
			identity_item.be_lib_number = ntohs(identity_item.be_lib_number);
			item_len += HTTC_ALIGN_SIZE((sizeof(struct process_identity) +
										 identity_item.be_hash_length * (1 + identity_item.be_lib_number) + identity_item.name_length),
										4);
		}
		if (item_len != ntohl(update->be_data_length))
		{
			httc_util_pr_error("para dmeasure process item_data_size=%d,update->be_data_length = %d\n", item_len, ntohl(update->be_data_length));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	} while (0);

	return rc;
}

int tcs_util_check_process_role_update(struct process_role_update *update)
{

	uint32_t rc = TPCM_SUCCESS;
	struct process_role item;
	uint32_t item_len = 0;
uint64_t replay_counter;
	uint32_t i = 0;
	do
	{

	
		if (ntohl(update->be_size) != sizeof(struct process_role_update))
		{
			httc_util_pr_error("update->be_size[%lu] != [%lu]\n", (unsigned long)ntohl(update->be_size), (unsigned long)sizeof(struct process_role_update));
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		
		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
	
		if ( ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("be_action[%d] not support\n", update->be_action);
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		//httc_util_pr_dev("r:update->be_item_number:%d\r\n",ntohl(update->be_item_number));
		for (i = 0; i < ntohl(update->be_item_number); i++)
		{
			memcpy(&item, update->data + item_len, sizeof(struct process_role));
			item.be_name_length = ntohl(item.be_name_length);
			item.be_members_length = ntohl(item.be_members_length);
			item.be_members_number = ntohl(item.be_members_number);
			//httc_util_pr_dev("item.be_members_number:%d item.be_name_length:%d: item.be_members_length:%d\r\n", item.be_members_number, item.be_name_length, item.be_members_length);
			item_len += HTTC_ALIGN_SIZE((sizeof(struct process_role) + item.be_name_length + item.be_members_length), 4);
		}

		if (item_len != ntohl(update->be_data_length))
		{
			httc_util_pr_error("para dmeasure process item_data_size=%d,update->be_data_length = %d\n", item_len, ntohl(update->be_data_length));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	} while (0);

	return rc;
}
int tcs_util_check_ptrace_protect_update(struct ptrace_protect_update *update)
{
	uint32_t rc = TPCM_SUCCESS;
	struct ptrace_protect *protect_item;
	struct process_name *be_ptracer_item;
	uint32_t be_name_length=0;
uint64_t replay_counter=0;
	uint32_t i = 0;
	uint32_t be_ptracer_item_len = 0;

	// httc_util_pr_dev("ptrace_protect_update:\r\n");
	//   httc_util_dump_hex(update, 128);

	do
	{

		

		if ( ntohl(update->be_size) != sizeof(struct ptrace_protect_update) )
		{
			httc_util_pr_error("update->be_size[%lu] != [%lu]\n",  (unsigned long)ntohl(update->be_size), (unsigned long)(sizeof(struct ptrace_protect_update) + sizeof(struct ptrace_protect) - sizeof(char *)));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		

		if ( ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("be_action[%d] not support\n",  ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n", (unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		

		//  httc_util_pr_dev(" update->be_data_length:%d\r\n", update->be_data_length);

		protect_item = update->data;

		//  httc_util_pr_dev("dump protect_item:\r\n");
		//  httc_util_dump_hex(protect_item, ntohl(update->be_data_length));

	

		if ((ntohl(protect_item->be_ptrace_protect) < 0) || (ntohl(protect_item->be_ptrace_protect) >= 2))
		{
			httc_util_pr_error("protect_item->be_ptrace_protect[%d] not support\n",ntohl(protect_item->be_ptrace_protect));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		//  httc_util_pr_dev("dump process:\r\n");
		//  httc_util_dump_hex(protect_item->process_names, 96);
		for (i = 0; i < (ntohl(protect_item->be_ptracer_number) + ntohl(protect_item->be_non_tracee_number)); i++)
		{
			be_ptracer_item = (struct process_name *)(protect_item->process_names + be_ptracer_item_len);
			 be_name_length = htonl(be_ptracer_item->be_name_length);

			be_ptracer_item_len += sizeof(struct process_name) + HTTC_ALIGN_SIZE((be_name_length), 4);
		}

		if (be_ptracer_item_len != ntohl(protect_item->be_total_length))
		{
			httc_util_pr_error("para dmeasure process item_data_size=%d,protect_item->be_total_length = %d\n", be_ptracer_item_len, ntohl(protect_item->be_total_length));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

	} while (0);

	return rc;
}
int tcs_util_check_tnc_policy_update(struct tnc_policy_update *update)
{
	uint32_t rc = 0;
	struct tnc_policy policy_data;
uint64_t replay_counter=0;
	do
	{

		if (ntohl(update->be_size) != sizeof(struct tnc_policy_update))
		{
			httc_util_pr_error("be_size[%d] \n", ntohl(update->be_size));
			// httc_util_pr_error("(sizeof(struct update_trusted_link_policy_cmd)): [%d]\n", (uint32_t)(sizeof(struct update_trusted_link_policy_cmd)));

			rc = TSS_ERR_BAD_DATA;
			break;
		}

		if (ntohl(update->be_action) != POLICY_ACTION_SET)
		{
			httc_util_pr_error("be_action[%lu] not support\n", (unsigned long)ntohl(update->be_action));
			rc = TSS_ERR_INVALID_ACTION;
			break;
		}

		replay_counter = ntohll(update->be_replay_counter);

		if (tcs_util_write_replay_counter(replay_counter) != 0)
		{

			httc_util_pr_error("replay error update->be_replay_counter:%llu\r\n",(unsigned long long)replay_counter);
			rc = TSS_ERR_VERIFY_REPLAY;
			break;
		}

		if (check_tpcm_id_func(update->tpcm_id, MAX_TPCM_ID_SIZE) != 0)
		{
			httc_util_pr_error("tpcm id is error\r\n");
			rc = TSS_ERR_TPCM_ID;
			break;
		}
		if (sizeof(struct tnc_policy) + ntohl(update->policy->be_exception_number) * sizeof(struct tnc_policy_item) != ntohl(update->be_data_length))
		{
			httc_util_pr_error("data_len[%lu] != [%lu]\n", (unsigned long)ntohl(update->be_data_length),
					(unsigned long) (sizeof(struct tnc_policy) + ntohl(update->policy->be_exception_number) * sizeof(struct tnc_policy_item)));
			rc = TSS_ERR_BAD_DATA;
			break;
		}

		policy_data.be_server_ip = ntohl(update->policy->be_server_ip);

		policy_data.be_server_port = ntohs(update->policy->be_server_port);

		policy_data.be_control_mode = ntohs(update->policy->be_control_mode);

		if (policy_data.be_control_mode > CONTROL_OK)
		{
			httc_util_pr_error("policy_data.control_mode[%d]", policy_data.be_control_mode);
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		policy_data.encrypt_auth = update->policy->encrypt_auth;

		if (policy_data.encrypt_auth > CONTROL_OK)
		{
			httc_util_pr_error("policy_data.encrypt_auth[%d]", policy_data.encrypt_auth);
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		policy_data.server_testify = update->policy->server_testify;

		if (policy_data.server_testify > CONTROL_OK)
		{
			httc_util_pr_error("policy_data.server_testify[%d]", policy_data.server_testify);
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		policy_data.report_auth_fail = update->policy->report_auth_fail;

		if (policy_data.report_auth_fail > CONTROL_OK)
		{
			httc_util_pr_error("policy_data.report_auth_fail[%d]", policy_data.report_auth_fail);
			rc = TSS_ERR_BAD_DATA;
			break;
		}
		policy_data.report_session = update->policy->report_session;
		if (policy_data.report_session > CONTROL_OK)
		{
			httc_util_pr_error("policy_data.report_session[%d]", policy_data.report_session);

			rc = TSS_ERR_BAD_DATA;
			break;
		}
		policy_data.be_session_expire = ntohl(update->policy->be_session_expire);
		//httc_util_pr_dev("be_session_expire[0x%x]\n", policy_data.be_session_expire);
		policy_data.be_exception_number = ntohl(update->policy->be_exception_number);
		if (policy_data.be_exception_number > 60)
		{
			httc_util_pr_error("policy_data.be_exception_number[%d]", policy_data.be_exception_number);
			rc = TSS_ERR_BAD_DATA;
			break;
		}
	} while (0);

	return rc;
}



int tcs_util_calc_policy_hash (struct admin_auth_policy *policy, unsigned char *hash, int *hash_len)
{
	
	int policy_flag = 0;
	sm3_context ctx;
	
#ifndef TSS_DEBUG
	int ret = 0;
	uint8_t process_or_role[MAX_PROCESS_NAME_LENGTH] = {0};
	int process_length = MAX_PROCESS_NAME_LENGTH;
	uid_t uid = -1;
	gid_t gid = -1;	
#endif


	*hash_len = 0;
	policy_flag = ntohl (policy->be_policy_flags);
	
	sm3_init (&ctx);
	sm3_update (&ctx, (const unsigned char *)&(policy->be_policy_flags), sizeof (policy->be_policy_flags));
	httc_util_pr_dev ("policy->be_policy_flags: 0x%x\n", policy->be_policy_flags);
#ifndef TSS_DEBUG
	if ( policy_flag & POLICY_FLAG_ENV){
		if (0 != (ret = tsb_measure_kernel_memory_all ())){
            httc_util_pr_error ("tsb_measure_kernel_memory_all error: %d(0x%x)\n", ret, ret);
			return TSS_ERR_ADMIN_AUTH;
		}
	}
#endif

#ifndef TSS_DEBUG
	if(policy_flag & POLICY_FLAG_USER_ID){
		uid = getuid();		
		sm3_update (&ctx, (const unsigned char *)&(uid), sizeof(unsigned int));
	}else if(policy_flag & POLICY_FLAG_GROUP_ID){
		gid = getgid();
		sm3_update (&ctx, (const unsigned char *)&(gid), sizeof(unsigned int));
	}
	if(policy_flag & POLICY_FLAG_PROCESS_IDENTITY){
		ret = tsb_get_process_identity(process_or_role,&process_length);
		if(ret){
			httc_util_pr_error("Error tsb_get_process_identity %d",ret);
			return TSS_ERR_ADMIN_AUTH;
		}			
		sm3_update (&ctx, (const unsigned char *)process_or_role, strlen ((const char *)process_or_role));
	}
	if(policy_flag & POLICY_FLAG_PROCESS_ROLE){
		
		if( !tsb_is_role_member((const unsigned char *)policy->process_or_role)){
			httc_util_pr_error("Error tsb_is_role_member %s",policy->process_or_role);
			return TSS_ERR_ADMIN_AUTH;
		}
		sm3_update (&ctx, (const unsigned char *)policy->process_or_role, MIN(strlen((const char *)policy->process_or_role),MAX_PROCESS_NAME_LENGTH));
	}
#else
	if(policy_flag & POLICY_FLAG_USER_ID || policy_flag & POLICY_FLAG_GROUP_ID){
		httc_util_pr_dev ("policy->be_user_or_group: 0x%x\n", policy->be_user_or_group);
		sm3_update (&ctx, (const unsigned char *)&(policy->be_user_or_group), sizeof (unsigned int));
	}
	if(policy_flag & POLICY_FLAG_PROCESS_IDENTITY || policy_flag & POLICY_FLAG_PROCESS_ROLE){
		httc_util_dump_hex ("policy->process_or_role", policy->process_or_role, MIN(strlen((const char *)policy->process_or_role),MAX_PROCESS_NAME_LENGTH));
        sm3_update (&ctx, (const unsigned char *)policy->process_or_role, MIN(strlen((const char *)policy->process_or_role),MAX_PROCESS_NAME_LENGTH));
	}
#endif
	sm3_finish (&ctx, hash);
	*hash_len = DEFAULT_HASH_SIZE;
	
	return TSS_SUCCESS;
}
extern int httc_get_admin_auth_policy(int id ,struct admin_auth_policy *policy);

int tcs_util_verify_update_by_admin_auth_policy(int id, int hash_len, unsigned char *hash)
{
	int ret=0;
	struct admin_auth_policy policy;
	uint8_t output[DEFAULT_HASH_SIZE];
	sm3_context ctx;
	
//	 int *olen=NULL;
 //  int ilen;
	if (id >= TPCM_ADMIN_AUTH_POLICY_MAX || (id < TPCM_ADMIN_AUTH_POLICY_BOOT_REF))
		{
			httc_util_pr_error("id[%d] >= %d\r\n", id, TPCM_ADMIN_AUTH_POLICY_MAX);
			ret = TSS_ERR_BAD_DATA;
			return ret;
		}

	if ((ret= httc_get_admin_auth_policy(id ,&policy)))
	{
		httc_util_pr_error("get id[%d] admin auth policy error ret= %d\r\n", id, ret);
	
		return ret;
	}

 	sm3_init (&ctx);
	httc_util_pr_dev ("policy.be_policy_flags: 0x%x\n", policy.be_policy_flags);
	sm3_update (&ctx, (uint8_t *)&policy.be_policy_flags, sizeof (policy.be_policy_flags));
 	if ((ntohl(policy.be_policy_flags) & POLICY_FLAG_USER_ID)
		|| (ntohl(policy.be_policy_flags) & POLICY_FLAG_GROUP_ID)){
		httc_util_pr_dev ("policy.be_user_or_group: 0x%x\n", policy.be_user_or_group);
		sm3_update (&ctx, (uint8_t *)&policy.be_user_or_group, sizeof (policy.be_policy_flags));
 	}
	if ((ntohl(policy.be_policy_flags) & POLICY_FLAG_PROCESS_IDENTITY)
		|| (ntohl(policy.be_policy_flags) & POLICY_FLAG_PROCESS_ROLE)){
		httc_util_dump_hex ("policy.process_or_role", policy.process_or_role, MIN(strlen ((char *)policy.process_or_role), MAX_PROCESS_NAME_LENGTH));
		sm3_update (&ctx, policy.process_or_role, MIN(strlen ((char *)policy.process_or_role), MAX_PROCESS_NAME_LENGTH));
	}
	sm3_finish (&ctx, output);
	
	if((ret=memcmp(hash,output,32)))
	{
		httc_util_pr_error("auth not equal policy \r\n");
		httc_util_dump_hex("hash", hash, 32);
		httc_util_dump_hex("policy", output, 32);
		return TSS_ERR_ADMIN_AUTH;
	}
	return ret;
}

int tcs_util_update_policy(	const char *uid,	int auth_type, int auth_length,unsigned char *auth, void *data, int data_len, 
								const char* path, void *policy, int policy_size, int num, int policy_type ,int action, uint64_t counter){

	int ret = 0;
	struct admin_cert_item cert;
	unsigned int com = 0;
	unsigned int version_type = 0;

	/*Get cert*/
	if( 0 != (ret = tcs_util_get_cert_by_uid ((const char *)uid, &cert))) return ret; 
	/*Verify update*/
	if(auth == NULL || auth_length == 0) return TSS_ERR_PARAMETER;
	if( 0 != (ret = tcs_util_verify_update(&cert, auth_type, auth_length, auth, data, data_len))) return ret; 
	/*Check policy*/
	switch (policy_type)
		{
			case TCS_POLICY_TYPE_ADMIN_AUTH_POLICY:
				if( 0 != (ret = tcs_util_check_admin_auth_policy_update ((struct admin_auth_policy_update *)data))) return ret;
				com = TPCM_ORD_SetAdminAuthPolicies;
				version_type = POLICY_TYPE_ADMIN_AUTH_POLICY;
				break;
			case TCS_POLICY_TYPE_GLOBAL_CONTROL_POLICY:
				if( 0 != (ret = tcs_util_check_global_control_policy_update ((struct global_control_policy_update *)data))) return ret;
				com = TPCM_ORD_SetGlobalControlPolicy;
				version_type = POLICY_TYPE_GLOBAL_CONTROL_POLICY;
				break;
			case TCS_POLICY_TYPE_DMEASURE:
				if( 0 != (ret = tcs_util_check_dmeasure_policy_update ((struct dmeasure_policy_update *)data))) return ret;
				com = TPCM_ORD_SetSignDMeasurePolicy;
				version_type = POLICY_TYPE_DMEASURE;
				break;				
			case TCS_POLICY_TYPE_PROCESS_DMEASURE:
				if( 0 != (ret = tcs_util_check_dmeasure_process_policy_update ((struct dmeasure_process_policy_update *)data))) return ret;
				com = TPCM_ORD_UpdateDmeasureProcessPolicy;
				version_type = POLICY_TYPE_PROCESS_DMEASURE;
				break;
			case TCS_POLICY_TYPE_PROCESS_IDENTITY:
				if( 0 != (ret = tcs_util_check_process_identity_update ((struct process_identity_update *)data))) return ret;
				com = TPCM_ORD_UpdateProcessIdentity;
				version_type = POLICY_TYPE_PROCESS_IDENTITY;
				break;
			case TCS_POLICY_TYPE_PROCESS_ROLE:
				if( 0 != (ret = tcs_util_check_process_role_update ((struct process_role_update *)data))) return ret;
				com = TPCM_ORD_UpdateProcessRoles;
				version_type = POLICY_TYPE_PROCESS_ROLE;
				break;
			case TCS_POLICY_TYPE_PTRACE_PROTECT:
				if( 0 != (ret = tcs_util_check_ptrace_protect_update ((struct ptrace_protect_update *)data))) return ret;
				com = TPCM_ORD_UpdatePtraceProtectsPolicy;
				version_type = POLICY_TYPE_PTRACE_PROTECT;
				break;
			case TCS_POLICY_TYPE_TNC:
				if( 0 != (ret = tcs_util_check_tnc_policy_update ((struct tnc_policy_update *)data))) return ret;
				com = TPCM_ORD_UpdateTncPolicy;
				version_type = POLICY_TYPE_TNC;
				break;
			case TCS_POLICY_TYPE_CRITICAL_FILE_INTEGRITY:
				if( 0 != (ret = tcs_util_check_critical_file_integrity_update ((struct file_integrity_update *)data))) return ret;
				com = TPCM_ORD_UpdateCriticalFileIntergrity;
				version_type = POLICY_TYPE_CRITICAL_FILE_INTEGRITY;
				break;
			case TCS_POLICY_TYPE_FILE_PROTECT:
				if( 0 != (ret = tcs_util_check_file_protect_update ((struct file_protect_update *)data))) return ret;
				com = TPCM_ORD_UpdateFileProtectPolicy;
				version_type = POLICY_TYPE_FILE_PROTECT;
				
				break;
			default:
				printf("error policy type %d\n",policy_type);
				ret = TSS_ERR_PARAMETER;
				return ret;
				break;		
		
		}
	/*Update policy*/
	if( 0 != (ret = tcs_util_write_policy (path, policy, policy_size, num))) return ret;
	/*Update policy version*/
	if( 0 != (ret = tcs_util_write_policy_version (version_type, counter))) return ret;
	/*Notification kernel*/
	if( 0 != (ret = tcs_util_inform_kernel_of_update (com, policy, policy_size, num))) return ret;
	return ret;
}


