#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "tdd.h"
#include "tddl.h"
#include "kutils.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "tcs_error.h"
#include "tcs_kernel.h"
#include "tcs_constant.h"
#include "tcs_tpcm_error.h"

#include "memdebug.h"
#include "debug.h"

extern uint32_t gui_trust_status;
extern uint32_t dmeasure_trust_status;
extern uint32_t intercept_trust_status;

#pragma pack(push, 1)

typedef struct{
	RESPONSE_HEADER;
	uint64_t host_startup_time;
	struct tsb_runtime_info info;
}tcs_rsp_trust_input_info;

typedef struct{
	COMMAND_HEADER;
	uint32_t index;
	uint32_t data_len;
	uint32_t passwd_len;
	uint8_t data_passwd[0];
}save_data_passwd_pag;

typedef struct{
	COMMAND_HEADER;
	uint32_t index;
	uint32_t passwd_len;
	uint8_t passwd[0];
}get_data_passwd_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t data_len;
	uint8_t data[0];
}get_data_passwd_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t uimaxlength;
}get_tpcmlog_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t uiLogNumber;
	uint8_t uaLog[0];
}get_tpcmlog_rsp_st;

typedef struct {
	RESPONSE_HEADER;
	uint8_t hash[DEFAULT_HASH_SIZE];
}get_file_integrity_digest_rsp_st;

typedef struct {
	COMMAND_HEADER;
	uint32_t be_type;
}sync_trust_status_req;

typedef struct {
	COMMAND_HEADER;
	struct kernel_section_info kernel_sec;
}kernel_section_req;

#pragma pack(pop)


static DEFINE_MUTEX(env_lock);
static DEFINE_MUTEX(pid_lock);
static DEFINE_MUTEX(kernel_lock);

static tsb_runtime_info_getter get_info_func = NULL;
static tsb_measure_env measure_env_func = NULL;
static struct process_identity_callback *process_identity_callback_func = NULL;


int tcsk_register_tsb_measure_env_callback (tsb_measure_env callback){
	mutex_lock(&env_lock);
	if(measure_env_func != NULL){
		httc_util_pr_error ("multiple registration!\n");		
		mutex_unlock(&env_lock);
		return -1;
	}
	measure_env_func = callback;
	mutex_unlock(&env_lock);
	return 0;
}
EXPORT_SYMBOL_GPL (tcsk_register_tsb_measure_env_callback);
int tcsk_unregister_tsb_measure_env_callback (tsb_measure_env callback){
	mutex_lock (&env_lock);
	if (measure_env_func != callback){
		httc_util_pr_error ("invalid unregistration func addr\n");
		mutex_unlock (&env_lock);
		return -1;
	}else{
		measure_env_func = NULL;
	}
	mutex_unlock (&env_lock);
	return 0;
}
EXPORT_SYMBOL_GPL (tcsk_unregister_tsb_measure_env_callback);

int tcsk_register_process_identity_callback(
		struct process_identity_callback *process_identity_callback)
{
	mutex_lock(&pid_lock);
	if(process_identity_callback_func != NULL){
		httc_util_pr_error ("multiple registration!\n");		
		mutex_unlock(&pid_lock);
		return -1;
	}
	process_identity_callback_func = process_identity_callback;
	mutex_unlock(&pid_lock);
	return 0;
}
EXPORT_SYMBOL_GPL (tcsk_register_process_identity_callback);

int tcsk_unregister_process_identity_callback(
		struct process_identity_callback *process_identity_callback)
{
	mutex_lock (&pid_lock);
	if (process_identity_callback_func != process_identity_callback){
		httc_util_pr_error ("invalid unregistration func addr\n");
		mutex_unlock (&pid_lock);
		return -1;
	}else{
		process_identity_callback_func = NULL;
	}
	mutex_unlock (&pid_lock);
	return 0;
}
EXPORT_SYMBOL_GPL (tcsk_unregister_process_identity_callback);

int tcs_util_tsb_measure_env (void)
{
	int ret = -1;
	mutex_lock (&env_lock);
	if (measure_env_func)
		ret = measure_env_func ();
	mutex_unlock (&env_lock);
	return ret;
}
int tcs_util_get_process_identity (unsigned char *process_name, int *process_name_length)
{
	int ret = -1;
	mutex_lock (&pid_lock);
	if (process_identity_callback_func && process_identity_callback_func->get_process_identity )
		ret = process_identity_callback_func->get_process_identity (process_name, process_name_length);
	mutex_unlock (&pid_lock);
	return ret;
}

int tcs_util_is_role_member (const unsigned char *role_name)
{
	int ret = -1;
	mutex_lock (&pid_lock);
	if (process_identity_callback_func && process_identity_callback_func->is_role_member)
		ret = process_identity_callback_func->is_role_member (role_name);
	mutex_unlock (&pid_lock);
	return ret;
}

int tcsk_register_tsb_runtime_info_getter(tsb_runtime_info_getter getter ){

	mutex_lock(&kernel_lock);
	if(get_info_func != 0){
		httc_util_pr_error ("multiple registration!\n");		
		mutex_unlock(&kernel_lock);
		return -1;
	}
	get_info_func = getter;
	mutex_unlock(&kernel_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tcsk_register_tsb_runtime_info_getter);

int tcsk_unregister_tsb_runtime_info_getter(tsb_runtime_info_getter getter ){
	
	mutex_lock(&kernel_lock);
	if(getter == get_info_func) get_info_func = 0;
	else{
		httc_util_pr_error ("invalid unregistration func addr = %p\n",getter);
		mutex_unlock(&kernel_lock);
	}
	mutex_unlock(&kernel_lock);
	return 0;

}
EXPORT_SYMBOL_GPL(tcsk_unregister_tsb_runtime_info_getter);


/*
 * 保存易失数据
 */
int tcsk_save_mem_data(uint32_t index, int length, unsigned char *data, char *usepasswd)
{
	int ret = 0; 
    int pb_len = 0, db_len = 0;
	uint32_t cmdLen = 0;
    char b_buf[4] = {0};
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	int total_len = 0, passwd_len = 0;
	save_data_passwd_pag *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	passwd_len = strlen(usepasswd);
	total_len = length + passwd_len;

	if((int)(CMD_DEFAULT_ALLOC_SIZE - sizeof(save_data_passwd_pag)) < total_len) {
		httc_util_pr_error ("total_len is too large (%d > %d)\n",
				total_len, (int)(CMD_DEFAULT_ALLOC_SIZE - sizeof(save_data_passwd_pag)));
		return TSS_ERR_INPUT_EXCEED;
	}

	if((cmd = (save_data_passwd_pag*)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	if((rsp = (tpcm_rsp_header_st*)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer(cmd);
		return TSS_ERR_NOMEM;
	}

	//cmdLen = sizeof(save_data_passwd_pag);
	cmdLen = sizeof(save_data_passwd_pag) + total_len;
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdCode = htonl(TPCM_ORD_SaveMemData);
	cmd->index = htonl(index);
	cmd->data_len = htonl(length);
	cmd->passwd_len = htonl(passwd_len);

    if((db_len = (length % 4)) != 0)
    {
        tpcm_memcpy(data + length, b_buf, (4 - db_len));
    }
    if(db_len == 0){
        tpcm_memcpy(cmd->data_passwd, data, length + db_len);
    }
    else{
        db_len = 4 - db_len;
        tpcm_memcpy(cmd->data_passwd, data, length + db_len);
    }

    if((pb_len = (passwd_len % 4)) != 0)
    {
        tpcm_memcpy(usepasswd + passwd_len, b_buf, (4 - pb_len));
    }
    if(pb_len == 0){
        tpcm_memcpy(cmd->data_passwd + length + db_len, usepasswd, passwd_len + pb_len);
    }
    else{
        pb_len = 4 - pb_len;
        tpcm_memcpy(cmd->data_passwd + length + db_len, usepasswd, passwd_len + pb_len);
    }
    cmdLen = cmdLen + db_len + pb_len;
	cmd->uiCmdLength = htonl(cmdLen);
/*
    data_bag_len = httc_insert_data_align4((char *)data, length, (char *)cmd + sizeof(save_data_passwd_pag));
    passwd_bag_len = httc_insert_data((char *)usepasswd, passwd_len, (char *)cmd + sizeof(save_data_passwd_pag) + data_bag_len);
    cmdLen = cmdLen + data_bag_len + passwd_bag_len;
*/

	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}

	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(tpcm_rsp_header_st)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
	}

out:	
	if(cmd) {
		tdd_free_data_buffer(cmd);
	}
	
	if(rsp) {
		tdd_free_data_buffer(rsp);
	}
	
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_save_mem_data);

int tcsk_read_mem_data(uint32_t index, int *length_inout, unsigned char *data, char *usepasswd)
{
	int ret = 0;
    int pb_len = 0;
	uint32_t cmdLen = 0;
    char b_buf[4] = {0};
	uint32_t rspLen = CMD_DEFAULT_ALLOC_SIZE;
	int passwd_len = 0;
	get_data_passwd_req_st *cmd = NULL;
	get_data_passwd_rsp_st *rsp = NULL;

	passwd_len = strlen(usepasswd);

	if((cmd = (get_data_passwd_req_st*)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}

	if((rsp = (get_data_passwd_rsp_st*)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer(cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof(get_data_passwd_req_st) + passwd_len;
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdCode = htonl(TPCM_ORD_ReadMemData);
	cmd->index = htonl(index);
	cmd->passwd_len = htonl(passwd_len);
    if((pb_len = (passwd_len % 4)) != 0)
    {
        tpcm_memcpy(usepasswd + passwd_len, b_buf, (4 - pb_len));
    }
    if(pb_len == 0){
	    tpcm_memcpy(cmd->passwd, usepasswd, passwd_len + pb_len);
    }
    else{
        pb_len = 4 - pb_len;
	    tpcm_memcpy(cmd->passwd, usepasswd, passwd_len + pb_len);
    }
    cmdLen = cmdLen + pb_len;
	cmd->uiCmdLength = htonl(cmdLen);

	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, (int *)&rspLen)) != 0) {
		goto out;
	}
	if(tpcmRspTag(rsp) != TPCM_TAG_RSP_COMMAND) {
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(ntohl(rsp->data_len) > *length_inout) {
			//ret = TSS_ERR_BAD_RESPONSE; //problem
	        ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		tpcm_memcpy(data, rsp->data, ntohl(rsp->data_len));
		*length_inout = ntohl(rsp->data_len);
	}

out:	
	if(cmd) {
		tdd_free_data_buffer (cmd);
	}
	
	if(rsp) {
		tdd_free_data_buffer (rsp);
	}
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_read_mem_data);

int tcs_get_tsb_trust_info(struct tsb_runtime_info * info){

	int ret = 0;
	struct tsb_runtime_info *tsbinfo = NULL;
	
	if (NULL == (tsbinfo = (struct tsb_runtime_info *)httc_vmalloc (sizeof(struct tsb_runtime_info)))){
		httc_util_pr_error ("Req Alloc hter!\n");
		ret = TSS_ERR_NOMEM;
		return ret;
	}	
	
	mutex_lock(&kernel_lock);
	if(get_info_func){
		get_info_func(tsbinfo);
		tpcm_memcpy(info, tsbinfo, sizeof(struct tsb_runtime_info));
		ret = 0;
	}else{
		httc_util_pr_dev ("Invalid get_info_func!\n");
	}
	mutex_unlock(&kernel_lock);
	if(tsbinfo) httc_vfree(tsbinfo);
	return ret;
}

int tcsk_get_tpcm_log (uint32_t *length, uint8_t *log, uint32_t *tpcmRes)
{
	int ret = 0;
	uint32_t cmdLen = 0;
	uint32_t rspLen = sizeof(get_tpcmlog_rsp_st) + *length;
	get_tpcmlog_req_st *cmd = NULL;
	get_tpcmlog_rsp_st *rsp = NULL;
	
	if (NULL == (cmd = (get_tpcmlog_req_st *)tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	if (NULL == (rsp = (get_tpcmlog_rsp_st *)tdd_alloc_data_buffer (rspLen))){
		httc_util_pr_error ("Rsp Alloc hter!\n");
		tdd_free_data_buffer (cmd);
		return TSS_ERR_NOMEM;
	}

	cmdLen = sizeof(get_tpcmlog_req_st);
	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_GetTpcmLog);
	cmd->uimaxlength = htonl(*length);
	
	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, (int *)&rspLen)))	goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}
	*tpcmRes = tpcmRspRetCode (rsp);
	if ((0 == *tpcmRes) || (TPCM_OUT_SIZE_EXCEEDED == *tpcmRes)){
		if ((int)(*length) < (int)(tpcmRspLength (rsp) - sizeof (get_tpcmlog_rsp_st))){
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*length = tpcmRspLength (rsp) - sizeof (get_tpcmlog_rsp_st);
		if (*length) tpcm_memcpy (log, rsp->uaLog, *length);
	}

out:
	if (cmd)	tdd_free_data_buffer (cmd);
	if (rsp)	tdd_free_data_buffer (rsp);
	//DEBUG (ret);
	return ret;
}
EXPORT_SYMBOL_GPL (tcsk_get_tpcm_log);

int tpcm_ioctl_sync_trust_status (uint8_t *ucmd, uint32_t ucmdLen, void *rsp, int *rspLen){

	int ret = 0;
	ret = tcsk_sync_trust_status(ntohl(((sync_trust_status_req *)ucmd)->be_type));	
	*rspLen = sizeof(tpcm_rsp_header_st);
	((tpcm_rsp_header_st *)rsp)->uiRspLength = htonl(*rspLen);
	((tpcm_rsp_header_st *)rsp)->uiRspRet = htonl(ret);
	((tpcm_rsp_header_st *)rsp)->uiRspTag = htonl(TPCM_TAG_RSP_COMMAND);
	return TSS_SUCCESS;
}

int tcsk_sync_trust_status(uint32_t type)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	sync_trust_status_req *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if((buffer = (uint8_t *)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (sync_trust_status_req *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	cmdLen = sizeof(sync_trust_status_req);	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_SyncTrustedStatus);	
	cmd->be_type = htonl(type);
	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, &rspLen)) != 0){
		goto out;
	}

	ret = tpcmRspRetCode(rsp);
	if (!ret){
		gui_trust_status = STATUS_UNTRUSTED;
		if(DYNAMIC_TRUST_STATE==type){
			dmeasure_trust_status = STATUS_UNTRUSTED;
		}
		if(INTERCEPT_TRUST_STATE==type){
			intercept_trust_status = STATUS_UNTRUSTED;
		}
	}

	printk (" >>> trust status updated: gui_trust_status: %d, dmeasure_trust_status: %d, intercept_trust_status: %d\n",
						gui_trust_status, dmeasure_trust_status, intercept_trust_status);

out:
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_sync_trust_status);


int tcsk_kernel_section_trust_status(struct kernel_section_info *kernel_section_para)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE/2;
	uint8_t *buffer = NULL;
	kernel_section_req *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if((buffer = (uint8_t *)tdd_alloc_data_buffer(CMD_DEFAULT_ALLOC_SIZE)) == NULL)
	{
		httc_util_pr_error("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	
	cmd = (kernel_section_req *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);
	cmdLen = sizeof(kernel_section_req);	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_UpdateKernelSectionStatus);	
	// cmd->kernel_sec.data_address = htonll(kernel_section_para->data_address);
	// cmd->kernel_sec.data_length=htonl(kernel_section_para->data_length);
	memcpy(cmd->kernel_sec.hash_data,kernel_section_para->hash_data,32);
	cmd->kernel_sec.measure_ret=htonl(kernel_section_para->measure_ret);
	memcpy(cmd->kernel_sec.obj_name,kernel_section_para->obj_name,MAX_DMEASURE_NAME_SIZE);

	if((ret = tpcm_tddl_transmit_cmd(cmd, cmdLen, rsp, &rspLen)) != 0){
		goto out;
	}

	ret = tpcmRspRetCode(rsp);
	if (!ret){
	printk (" kernelsection return :%d\n",ret);
	}



out:
	if(buffer) {
		tdd_free_data_buffer(buffer);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_kernel_section_trust_status);
/*
 *	获取文件完整性库hash
 */
int tcsk_get_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len){

	int ret = 0;
	int cmdLen = sizeof(tpcm_req_header_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_file_integrity_digest_rsp_st *rsp = NULL;

	if(digest == NULL || digest_len == NULL || *digest_len < DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buf;
	rsp = (get_file_integrity_digest_rsp_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetFileintergrityDigest);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	
	if(tpcmReqLength(rsp) != sizeof(get_file_integrity_digest_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(get_file_integrity_digest_rsp_st), tpcmReqLength(rsp));
		goto out;
	}
	tpcm_memcpy(digest,rsp->hash,DEFAULT_HASH_SIZE);
	*digest_len = DEFAULT_HASH_SIZE;
	ret = tpcmRspRetCode (rsp);
out:
	if (buf) tdd_free_data_buffer (buf);
	return ret;
}
EXPORT_SYMBOL_GPL(tcsk_get_file_integrity_digest);

/** 获取关键文件完整性基准库摘要值 */
int tcsk_get_critical_file_integrity_digest (unsigned char *digest ,unsigned int *digest_len)
{
	int ret = 0;
	int cmdLen = sizeof(tpcm_req_header_st);
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buf = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_file_integrity_digest_rsp_st *rsp = NULL;

	if(digest == NULL || digest_len == NULL || *digest_len < DEFAULT_HASH_SIZE) return TSS_ERR_PARAMETER;

	if (NULL == (buf = tdd_alloc_data_buffer (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc hter!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_req_header_st *)buf;
	rsp = (get_file_integrity_digest_rsp_st *)(buf + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetCriticalFileIntergrityDigest);

	if (0 != (ret = tpcm_tddl_transmit_cmd (cmd, cmdLen, rsp, &rspLen))) goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}

	if ((ret = tpcmRspRetCode (rsp))) goto out;
	if(tpcmReqLength(rsp) != sizeof(get_file_integrity_digest_rsp_st)){
		ret = TSS_ERR_BAD_RESPONSE;
		httc_util_pr_error ("hter response exp_length:%ld act_length:%d\n",
							(long int)sizeof(get_file_integrity_digest_rsp_st), tpcmReqLength(rsp));
		goto out;
	}
	tpcm_memcpy(digest,rsp->hash,DEFAULT_HASH_SIZE);
	*digest_len = DEFAULT_HASH_SIZE;

out:
	if (buf) tdd_free_data_buffer (buf);
	return ret;

}
EXPORT_SYMBOL_GPL(tcsk_get_critical_file_integrity_digest);


