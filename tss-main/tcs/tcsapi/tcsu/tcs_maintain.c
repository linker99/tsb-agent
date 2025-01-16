#include <stdio.h>
#include <stdint.h>

#include "mem.h"
#include "sys.h"
#include "uutils.h"
#include "debug.h"
#include "convert.h"

#include "tcmfunc.h"
#include "tcmutil.h"
#include "tcm_error.h"
#include "tcm_constants.h"
#include "tcs_error.h"
#include "tcs_maintain.h"
#include "tcs_constant.h"
#include "tcs_config.h"
#include "tpcm_command.h"
#include "transmit.h"

static const char *smkpwd = "httc@123";
static const char *ekpwd = "1234567812345678123456781234567812345678123456781234567812345678";

#pragma pack(push, 1)

typedef struct{
	COMMAND_HEADER;
	uint8_t fwBuf[0];
}fw_upgrade_user_req_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t length;
	uint8_t  data[0];
}tpcm_offline_req_st;

typedef struct{
	uint32_t command;
	uint32_t result;
}tpcm_offline_result_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t number;
	uint8_t  data[0];	//tpcm_offline_result_st
}tpcm_offline_rsp_st;


typedef struct{
	COMMAND_HEADER;
	uint32_t backup_key_len;
	uint8_t  backup_key[0];
}tpcm_backup_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t backup_data_len;
	uint8_t backup_data[0];
}tpcm_backup_rsp_st;

typedef struct{
	COMMAND_HEADER;
	uint32_t backup_key_len;
	uint32_t restore_data_len;
	uint8_t  data[0];	//backup_key + backup_data
}tpcm_restore_req_st;

typedef struct{
	RESPONSE_HEADER;
	uint32_t status;
}get_linked_switch_status_rsp;

#pragma pack(pop)

/*
 * 	初始化TPCM
 * 	如果需要，生成背书密钥
 * 	获取可信密码模块（TCM）的所有者权限。
 * 	需传入可信密码模块（TCM）的认证信息。
 *
 */
int tcs_init(unsigned char *passwd)
{
	uint32_t ret = 0;
	uint8_t ownauth[32] = {0};
	uint8_t smkauth[32] = {0};
	uint8_t ekauth[64] = {0};
	uint8_t ekauth_reset[64] = {0};
	unsigned char iv[16] = {0};
	keydata key;
	TCM_PCR_INFO pcrInfo;
	STACK_TCM_BUFFER(serPcrInfo);

	TCM_setlog(0);

	memset(&pcrInfo, 0x0, sizeof(pcrInfo));
	pcrInfo.tag = TCM_TAG_PCR_INFO;
	pcrInfo.localityAtCreation = TCM_LOC_ZERO;
	pcrInfo.localityAtRelease = TCM_LOC_ZERO;
	pcrInfo.PcrAtRelease.sizeOfSelect = 4;
	pcrInfo.PcrAtCreation.sizeOfSelect = 4;
	if(0 != (ret = TCM_Open())) goto out;
	ret = TCM_WritePCRInfo(&serPcrInfo, &pcrInfo);
	if (ret & ERR_MASK){
        httc_util_pr_error ("Error while serializing PCRInfo.\n");
        goto out;
    }
	httc_util_rand_bytes (iv, sizeof (iv));

	if (0 != (ret = TCM_Init ())){
		httc_util_pr_error ("Error %s from TCM_Init.\n", TCM_GetErrMsg(ret));
		goto out;
	}
	if (0 != (ret = TCM_Startup (TCM_ST_CLEAR))){
		httc_util_pr_error ("Error %s from TCM_Startup.\n", TCM_GetErrMsg(ret));
		goto out;
	}
	if (0 != (ret = TSC_PhysicalPresence (TCM_PHYSICAL_PRESENCE_CMD_ENABLE))){
		httc_util_pr_error ("Error %s from TSC_PhysicalPresence.\n", TCM_GetErrMsg(ret));
		goto out;
	}
	if (0 != (ret = TSC_PhysicalPresence (TCM_PHYSICAL_PRESENCE_PRESENT))){
		httc_util_pr_error ("Error %s from TSC_PhysicalPresence.\n", TCM_GetErrMsg(ret));
		goto out;
	}
	if (0 != (ret = TCM_PhysicalEnable (FALSE))){
		httc_util_pr_error ("Error %s from TCM_PhysicalEnable.\n", TCM_GetErrMsg(ret));
		goto out;
	}
	if (0 != (ret = TCM_PhysicalSetDeactivated (FALSE))){
		httc_util_pr_error ("Error %s from TCM_PhysicalSetDeactivated.\n", TCM_GetErrMsg(ret));
		goto out;
	}

	if (strlen ((const char *)ekpwd) != sizeof (ekauth)){
		httc_util_pr_error  ("Invalid EK passwd!\n");
		return TSS_ERR_PARAMETER;
	}
	httc_util_str2array (ekauth, (uint8_t *)ekpwd, strlen ((const char *)ekpwd));
	sm3 ((const unsigned char *)passwd, strlen ((const char *)passwd), ownauth);
	sm3 ((const unsigned char *)smkpwd, strlen ((const char *)smkpwd), smkauth);

	ret = TCM_CreateRevocableEK (FALSE, ekauth, ekauth_reset);
	if ((0 != ret) && (TCM_DISABLED_CMD != ret)){
		httc_util_pr_error ("Error %s from TCM_CreateRevocableEK.\n", TCM_GetErrMsg(ret));
		goto out;
	}

	ret = TCM_TakeOwnership (ownauth, smkauth,
			TCM_SM4_KEY_LENGTH, serPcrInfo.buffer, serPcrInfo.used, iv, &key);
	if ((0 != ret) && (TCM_OWNER_SET != ret)){
		httc_util_pr_error ("Error %s from TCM_TakeOwnership.\n", TCM_GetErrMsg(ret));
	}
	ret = TSS_SUCCESS;
out:
	 TCM_Close();
	return ret;
}

/*
 *	修改TCM所有者认证信息
 */
int tcs_change_tcm_owner_auth(unsigned char *oldpass,unsigned char *newpass)
{	
	int ret = 0;
	unsigned char *oldauth = NULL;
	unsigned char *newauth = NULL;
	unsigned char oldhash[DEFAULT_HASH_SIZE] = {0};
	unsigned char newhash[DEFAULT_HASH_SIZE] = {0};

	TCM_setlog(0);
	
	if (oldpass){
		sm3 (oldpass, strlen ((const char *)oldpass), oldhash);
		oldauth = oldhash;
	}
	if (newpass){
		sm3 (newpass, strlen ((const char *)newpass), newhash);
		newauth = newhash;
	}
	if(0 != (ret = TCM_Open())) return ret;
	ret = TCM_ChangeAuthOwner (oldauth, TCM_ET_OWNER, oldauth, newauth);
	TCM_Close();
	return ret;
}

/*
 * 	备份流程
 * 	1 生成备份的数据包（主要是SRK）
 * 	2 备份的数据包，先计算HASH,并先用管理员备份密钥加密（备份数据包 + HASH）。
 * 	3 生成厂商备份密钥，进行二次加密(第一轮加密的密文  + License信息 + HASH）
 * 	4 通过厂商公钥加密加密厂商备份密钥。
 *	backup_key//用于加密卡内部数据的对称，只有管理员知道密钥。
 */
int tcs_backup (uint32_t backup_key_len,const unsigned char *backup_key,unsigned char *backup_data,int *olen_inout)
{
	int ret = 0;
	int cmdLen = sizeof (tpcm_backup_req_st) + backup_key_len;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_backup_req_st *cmd = NULL;
	tpcm_backup_rsp_st *rsp = NULL;

	if (NULL == (cmd = (tpcm_backup_req_st *)httc_malloc (cmdLen + sizeof (tpcm_rsp_header_st) + *olen_inout))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tpcm_backup_rsp_st*)((void*)cmd + cmdLen);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (sizeof (tpcm_backup_req_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_Backup);
	cmd->backup_key_len = htonl (backup_key_len);
	memcpy (cmd->backup_key, backup_key, backup_key_len);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (sizeof (tpcm_backup_rsp_st) >= tpcmRspLength (rsp)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (tpcmRspLength (rsp) > *olen_inout){
			httc_util_pr_error ("Too large backup data (%d > %d).\n", tpcmRspLength (rsp), *olen_inout);
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*olen_inout = tpcmRspLength (rsp);
		memcpy (backup_data, rsp->backup_data, *olen_inout);
	}
out:
	if (cmd)	httc_free (cmd);
	return ret;
}


/*
 * 	TPCM备份恢复
 * 	用于灾难和事故恢复，涉及许可权限恢复，由管理员与TPCM厂商协同完成
 * 	恢复流程
 * 	0)  生成新的证书请求,与备份的数据一起提交给华泰。华泰生成恢复包,恢复包用新TPCM的背书密钥加密
 * 	1）  用背书密钥解密备份数据（主要是license和第一次密文）
 * 	2）  验证厂商签名
 * 	3）  用备份密钥解密第一层数据（主要是SRK），并验证完整性。
 * 	4）  恢复备份数据包（不包括license）
 * 	5)  导入新的license
 */
int tcs_restore(uint32_t restore_data_len, unsigned char *restore_data, uint32_t backup_key_len,const unsigned char *backup_key)
{
	int ret = 0;
	int cmdLen = sizeof (tpcm_restore_req_st) + restore_data_len + backup_key_len;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	tpcm_restore_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (cmd = (tpcm_restore_req_st *)httc_malloc (cmdLen + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tpcm_rsp_header_st*)((void*)cmd + cmdLen);

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (sizeof (tpcm_restore_req_st));
	cmd->uiCmdCode = htonl (TPCM_ORD_Restore);
	cmd->backup_key_len = htonl (backup_key_len);
	cmd->restore_data_len = htonl (backup_key_len);
	memcpy (cmd->data, backup_key, backup_key_len);
	memcpy (cmd->data + backup_key_len, restore_data, restore_data_len);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;

	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		goto out;
	}
	if (sizeof (tpcm_rsp_header_st) != tpcmRspLength (rsp)){
		httc_util_pr_error ("Invalid response steam.\n");
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);

out:
	if (cmd)	httc_free (cmd);
	return ret;
}


/*
 * 	升级TPCM固件。
 * 	与重置TPCM固件不同，升级会保留用户数据和许可权限
 * 	参照之前的升级包格式
 */
int tcs_upgrade(unsigned char *upgrade_data,int length)
{
	int ret = 0;
	int cmdLen = sizeof (fw_upgrade_user_req_st) + length;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE;
	fw_upgrade_user_req_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;

	if (NULL == (cmd = (fw_upgrade_user_req_st *)httc_malloc (cmdLen))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	rsp = (tpcm_rsp_header_st*)cmd;
	
	cmd->uiCmdTag = TPCM_TAG_REQ_COMMAND;
	cmd->uiCmdLength = cmdLen;
	cmd->uiCmdCode = TPCM_ORD_FirmwareUpgrade;
	memcpy (cmd->fwBuf, upgrade_data, length);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}
	ret = tpcmRspRetCode (rsp);
	
out:
	if (cmd) httc_free (cmd);
	return ret;
}

/*
 * 	设置TPCM控制台密码，
 * 	用于在不可重启机器的情况下，
 * 	修改控制策略，让机器可以正常启动并进行进一步维护管理。
 *	本接口改变TPCM控制台密码，提高TPCM自身的保护能力。
 */
int tcs_set_shell_password(struct shell_passwd *passwd,
		const char *uid, int auth_type, int auth_length, unsigned char *auth)
{
	/** 
		struct set_shell_password_req{
			COMMAND_HEADER;
			struct tpcm_data uid;
			struct tpcm_auth auth;
			struct dmeasure_policy_update *policy;
		};
	*/
	int ret = 0;
	int size = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	int uid_len = 0;
	int auth_len = 0;
	int passwd_size = 0;
	
	uid_len = uid ? (strlen (uid) + 1) : 0;
	auth_len = auth ? auth_length : 0;
	passwd_size = sizeof (struct shell_passwd) + ntohl (passwd->be_password_length);
	size = passwd_size
				+ sizeof (struct tpcm_data) + uid_len
				+ sizeof (struct tpcm_auth) + auth_len;

	if (NULL == (buffer = httc_malloc (sizeof (tpcm_req_header_st) + size + CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
		
	cmd = (tpcm_req_header_st *)buffer;
	rsp = (tpcm_rsp_header_st *)(buffer + size);

	cmdLen = sizeof (tpcm_req_header_st);
	/** Insert uid, aligned (4)*/
	cmdLen += httc_insert_uid_align4 (uid, (void*)cmd + cmdLen);
	/** Insert auth, aligned (4) */
	cmdLen += httc_insert_auth_align4 (auth_type, auth_length, auth, (void*)cmd + cmdLen);	
	memcpy ((void*)cmd + cmdLen, passwd, passwd_size);
	cmdLen += passwd_size;

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_SetTpcmShellAuth);

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

/*
 * 执行离线命令
 * 在管理中心无法连接的情况，可导出离线命令，在本机执行。
 * 离线命令也可以由启动加载器发起
 * 如UEFI或GRUB，可通过发送离线命令改变控制策略，以便系统能够正常启动
 */
int tcs_exec_offline_cmd(const char *offcmd,int len, char *offres, int *olen)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	int offreslen = 0;
	tpcm_offline_req_st *cmd = NULL;
	tpcm_offline_rsp_st *rsp = NULL;
	
	if (NULL == (buffer = httc_malloc (CMD_DEFAULT_ALLOC_SIZE))){
		httc_util_pr_error ("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}
	cmd = (tpcm_offline_req_st *)buffer;
	rsp = (tpcm_offline_rsp_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	cmdLen = sizeof (tpcm_offline_req_st) + len;
	if (cmdLen > CMD_DEFAULT_ALLOC_SIZE){
		httc_free (buffer);
		httc_util_pr_error ("switch is too large!\n");
		return TSS_ERR_INPUT_EXCEED;
	}

	cmd->uiCmdTag = htonl (TPCM_TAG_REQ_COMMAND);	
	cmd->uiCmdLength = htonl (cmdLen);
	cmd->uiCmdCode = htonl (TPCM_ORD_TpcmOffCommand);
	cmd->length = htonl (len);
	memcpy(cmd->data,offcmd,len);

	if (0 != (ret = tpcm_transmit (cmd, cmdLen, rsp, &rspLen)))		goto out;
	
	if (TPCM_TAG_RSP_COMMAND != tpcmRspTag(rsp)){
		httc_util_pr_error ("Invalid tpcm rsp tag(0x%02X)\n", tpcmRspTag(rsp));
		ret = TSS_ERR_BAD_RESPONSE_TAG;
		goto out;
	}

	if (0 == (ret = tpcmRspRetCode (rsp))){
		if (tpcmRspLength(rsp) <= sizeof(tpcm_offline_rsp_st)){
			httc_util_pr_error ("Invalid response!\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		if ((ntohl(rsp->number) * 8) != (tpcmRspLength(rsp) - sizeof(tpcm_offline_rsp_st))){
			httc_util_pr_error ("Invalid response!\n");
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		offreslen = sizeof(rsp->number) + ntohl(rsp->number) * sizeof (tpcm_offline_result_st);
		if ((int)(*olen) < (int)offreslen){
			httc_util_pr_error ("out space is not enough (%d < %d)\n", *olen, offreslen);
			ret = TSS_ERR_OUTPUT_EXCEED;
			goto out;
		}
		*olen = sizeof(rsp->number) + ntohl(rsp->number) * 8;
		memcpy (offres, &(rsp->number), *olen);
	}
	
out:	
	if (buffer)	httc_free (buffer);
	return ret;	
}

/** 获取联动开关状态 */
int tcs_get_linked_switch_status (uint32_t *status)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	get_linked_switch_status_rsp *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_GetLinkedSwitchStatus);
	rsp = (get_linked_switch_status_rsp *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) 	goto out;

	if((ret = tpcmRspRetCode(rsp)) == 0) {
		if(tpcmRspLength(rsp) != sizeof(get_linked_switch_status_rsp)) {
			ret = TSS_ERR_BAD_RESPONSE;
			goto out;
		}
		*status = ntohl(rsp->status);
	}

out:	
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}

/** 清除联动开关状态 */
int tcs_clear_linked_switch_status (void)
{
	int ret = 0;
	int cmdLen = 0;
	int rspLen = CMD_DEFAULT_ALLOC_SIZE / 2;
	uint8_t *buffer = NULL;
	tpcm_req_header_st *cmd = NULL;
	tpcm_rsp_header_st *rsp = NULL;
	
	if((buffer = (uint8_t *)httc_malloc(CMD_DEFAULT_ALLOC_SIZE)) == NULL) {
		httc_util_pr_error("Req Alloc error!\n");
		return TSS_ERR_NOMEM;
	}

	cmd = (tpcm_req_header_st *)buffer;
	cmdLen = sizeof(tpcm_req_header_st);
	
	cmd->uiCmdTag = htonl(TPCM_TAG_REQ_COMMAND);
	cmd->uiCmdLength = htonl(cmdLen);
	cmd->uiCmdCode = htonl(TPCM_ORD_ClearLinkedSwitchStatus);
	rsp = (tpcm_rsp_header_st *)(buffer + CMD_DEFAULT_ALLOC_SIZE / 2);

	if((ret = tpcm_transmit(cmd, cmdLen, rsp, &rspLen)) != 0) 	goto out;

	if(tpcmRspLength(rsp) != sizeof(tpcm_rsp_header_st)) {
		ret = TSS_ERR_BAD_RESPONSE;
		goto out;
	}

	ret = tpcmRspRetCode(rsp);

out:	
	if(buffer) {
		httc_free(buffer);
	}
	
	return ret;
}
