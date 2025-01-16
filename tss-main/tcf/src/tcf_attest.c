#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcf.h"
#include "tutils.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include <httcutils/convert.h>
#include "tcsapi/tcs_attest.h"
#include "tcsapi/tcs_kernel.h"
#include "tcfapi/tcf_attest.h"
#include "tcfapi/tcf_file_integrity.h"
#include "tcfapi/tcf_error.h"
#include "tcsapi/tcs_constant.h"


/*
 * 	生成可信证明
 */
int tcf_generate_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,uint8_t * attached_hash)
{
	int ret = 0;
	unsigned char host_id[MAX_HOST_ID_SIZE] = {0};
	int host_id_len = MAX_HOST_ID_SIZE;
	if ((ret = tcf_get_host_id(host_id,&host_id_len))) return ret;
	return tcs_generate_trust_evidence (evidence, nonce, host_id, attached_hash);
}

/*
 * 	验证远程可信证明
 */
int tcf_verify_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,unsigned char *oid){
	return tcs_verify_trust_evidence (evidence, nonce, oid);
}


int tcf_get_ruida_ip(uint32_t *hostip, uint32_t *num){

	return tcs_get_ruida_ip(hostip, num);
}

/*
 * 	生成可信报告
 */
int tcf_generate_trust_report(struct trust_report *report,uint64_t nonce,uint32_t be_addr){

	int ret = 0;
	unsigned char id[MAX_HOST_ID_SIZE] = {0};
	int len_inout = MAX_HOST_ID_SIZE;

	ret = tcf_get_host_id(id,&len_inout);
	if(ret) return ret;

	return tcs_generate_trust_report (report,nonce,id,be_addr);
}

/*
 * 	验证可信报告
 */
int tcf_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid){
	return tcs_verify_trust_report (report, nonce, oid);
}

/*
 *	 获取本地可信状态
 */
int tcf_get_trust_status(uint32_t *status){
	return tcs_get_trust_status (status);
}

int is_intercept_measure_supported (void){
	int r;
	uint32_t features;

	if ((r = tcf_get_tpcm_features (&features))){
		httc_util_pr_error("get_tpcm_features error: %d(0x%x)\n", r, r);
		return 0;
	}
	return (features & (1 << TPCM_FEATURES_INTERCEPT_MEASURE));
}

/*
 *	获取TPCM信息
 */
int tcf_get_tpcm_info(struct tpcm_info *status){

	int ret = 0;
	uint32_t number = 0;

	ret = tcs_get_tpcm_info (status);

	if(!is_intercept_measure_supported()){
		ret = tcf_get_file_integrity_total_number(&number);
		if(ret) {
			httc_util_pr_error("tcf_get_file_integrity_total_number error %0xld(%d)\n",ret,ret);
			status->be_file_integrity_total = 0;
		}else{
			status->be_file_integrity_total = htonl(number);
		}

		number = 0;
		ret = tcf_get_file_integrity_valid_number(&number);
		if(ret){
			httc_util_pr_error("tcf_get_file_integrity_valid_number error %0xld(%d)\n",ret,ret);
		}else{
			status->be_file_integrity_valid = htonl(number);
		}
	}

	return ret;
}


/*
 *	获取驱动类型信息
 */
int tcf_get_tdd_info(struct tdd_info *info)
{
	return tcs_get_tdd_info (info);
}

/*
 * 	获取TPCM ID
 */
int tcf_get_tpcm_id(unsigned char *id,int *len_inout)
{
	return tcs_get_tpcm_id (id, len_inout);
}

/*
 * 	获取HOST ID
 */
int tcf_get_host_id(unsigned char *id,int *len_inout)
{
	return tcs_get_host_id(id, len_inout);
}

/*
 * 	设置HOST ID
 */
int tcf_set_host_id(unsigned char *id,int len)
{
	return tcs_set_host_id(id, len);
}

/*
 * 	获取TPCM特性
 */

int tcf_get_tpcm_features(uint32_t *features){
	return tcs_get_tpcm_features (features);
}

/*
 * 	获取TPCM身份密钥公钥
 */
int tcf_get_pik_pubkey(unsigned char *pubkey,int *len_inout){
	return tcs_get_pik_pubkey (pubkey, len_inout);
}


/*
 * 	生成TPCM身份密钥
 */
int tcf_generate_tpcm_pik(unsigned char *passwd){
	return tcs_generate_tpcm_pik (passwd);
}

/*
 * 	与对端进行远程证明
 */
int tcf_remote_attest(const char *peer){
	return 0;
}

/*
 * 	添加信任的远程证书
 */

int tcf_add_remote_cert(struct remote_cert *remote_cert){
	return tcs_add_remote_cert (remote_cert);
}
/*
 * 	删除信任的远程证书
 */
int tcf_remove_remote_cert(const char *id){
	return tcs_remove_remote_cert (id);
}

/*
 * 	获取信任的远程证书列表
 * 	返回所有证书的数组
 */
int tcf_get_remote_certs(struct remote_cert **remote_cert,int *number){
	return tcs_get_remote_certs (remote_cert, number);
}

/*
 * 	获取当前防重放计数
 */
int tcf_get_replay_counter (uint64_t *replay_counter){
	int ret = 0;

	ret =  tcs_get_replay_counter (replay_counter);
	if(ret) return ret;
	return ret;
}

/*
 * 获取策略版本列表(tpcm && tcm)
 * version : [策略(4字节) + 主版本(8字节) + 次版本(4字节)] * num
 */

#define TCF_EXPAND_VERSION ((POLICY_TYPE_CRITICAL_FILE_INTEGRITY - POLICY_TYPE_KEYTREE)\
			+ (POLICIES_TYPE_MAX - POLICY_TYPE_FILE_PROTECT))

int tcf_get_policies_version (struct policy_version_user *version, int *num_inout){

	int i = 0;
	int ret = 0;
	int num = POLICIES_TYPE_MAX-TCF_EXPAND_VERSION;
	uint64_t act_version = 0;
	struct policy_version ver[POLICIES_TYPE_MAX];

	const char *log_version_path=(const char *)HTTC_TSS_CONFIG_PATH"log.version";
	const char *notice_version_path=(const char *)HTTC_TSS_CONFIG_PATH"notice.version";
    const char *udisk_version_path=(const char *)HTTC_TSS_CONFIG_PATH"udisk.version";
	const char *cdrom_version_path=(const char *)HTTC_TSS_CONFIG_PATH"cdrom.version";
	const char *file_version_path=(const char *)HTTC_TSS_CONFIG_PATH"file.version";
	const char *network_version_path=(const char *)HTTC_TSS_CONFIG_PATH"network.version";
	FILE *fp = NULL;

	if(version == NULL || num_inout == NULL) return TCF_ERR_PARAMETER;

	ret = tcs_get_policies_version(ver, &num);
	if(ret){
		httc_util_pr_error("tcs_get_policies_version error: %d(0x%x)\n", ret, ret);
		return ret;
	}
	if(num + TCF_EXPAND_VERSION > *num_inout) return TCF_ERR_OUTPUT_EXCEED;
	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;

	for(; i < num; i++){

		version[i].type = ntohl(ver[i].be_policy);
		act_version = ntohll(ver[i].be_version);

		if(version[i].type == POLICY_TYPE_FILE_INTEGRITY){
			version[i].major = get_major_version(act_version);
			ret = httc_get_file_integrity_subver(version[i].major,&(version[i].minor));
			if(ret){
				httc_util_pr_error("httc_get_file_integrity_subver error %d\n",ret);
				return ret;
			}
		}else{
			version[i].major = act_version;
			version[i].minor = 0;
		}
	}

	/**Add log version**/
	version[i].type = POLICY_TYPE_LOG;
	fp = fopen(log_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read log version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;

	/**Add notice version**/
	version[i].type = POLICY_TYPE_NOTICE;
	fp = fopen(notice_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read notice version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;

		/**Add udisk version**/
	version[i].type = POLICY_TYPE_UDISK_PROTECT;
	fp = fopen(udisk_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read notice version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;
		/**Add cdrom version**/
	version[i].type = POLICY_TYPE_DEV_PROTECT;
	fp = fopen(cdrom_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read notice version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;

	/**Add file version**/
	version[i].type = POLICY_TYPE_FILE_PROTECT;
	fp = fopen(file_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read notice version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;


	/**Add network version**/
	version[i].type = POLICY_TYPE_NETWORK_CONTROL;
	fp = fopen(network_version_path,"r");
	if(fp == NULL){
		version[i].major = 0;
	}else{
		ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
		if(ret != sizeof(uint64_t)){
			httc_util_pr_error("read notice version error %d\n",ret);
			fclose(fp);
			tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return TCF_ERR_FILE;
		}
		version[i].major = act_version;
		fclose(fp);
	}
	version[i].minor = 0;
	i++;

	*num_inout = i;

	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
	return TCF_SUCCESS;

}

/*
 * 获取指定策略版本列表(tpcm策略)
 * version : [策略(4字节) + 主版本(8字节) + 次版本(4字节)]
 */

int tcf_get_one_policy_version (struct policy_version_user *version){

	int i = 0;
	int ret = 0;
	int num = 15;
	uint64_t act_version = 0;
	struct policy_version ver[15];
	const char *log_version_path=(const char *)HTTC_TSS_CONFIG_PATH"log.version";
	const char *notice_version_path=(const char *)HTTC_TSS_CONFIG_PATH"notice.version";
	const char *cdrom_version_path=(const char *)HTTC_TSS_CONFIG_PATH"cdrom.version";
	const char *udisk_version_path=(const char *)HTTC_TSS_CONFIG_PATH"udisk.version";
	const char *file_version_path=(const char *)HTTC_TSS_CONFIG_PATH"file.version";
	const char *network_version_path=(const char *)HTTC_TSS_CONFIG_PATH"network.version";

	FILE *fp = NULL;

	if(version->type >= POLICIES_TYPE_MAX ||  version->type < 0) return TCF_ERR_PARAMETER;

	if ((ret = tcf_util_sem_get (TCF_SEM_INDEX_POLICY)))	return ret;

	if(version->type == POLICY_TYPE_LOG){
		fp = fopen(log_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read log version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}else if(version->type == POLICY_TYPE_NOTICE){
		fp = fopen(notice_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read notice version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}else if(version->type == POLICY_TYPE_DEV_PROTECT){
		fp = fopen(cdrom_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read notice version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}else if(version->type == POLICY_TYPE_UDISK_PROTECT){
		fp = fopen(udisk_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read notice version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}else if(version->type == POLICY_TYPE_FILE_PROTECT){
		fp = fopen(file_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read notice version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}
	else if(version->type == POLICY_TYPE_NETWORK_CONTROL){
		fp = fopen(network_version_path,"r");
		if(fp == NULL){
			version->major = 0;
		}else{
			ret = fread((char *)&act_version,1,sizeof(uint64_t),fp);
			if(ret != sizeof(uint64_t)){
				httc_util_pr_error("read notice version error %d\n",ret);
				fclose(fp);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
				return TCF_ERR_FILE;
			}
			version->major = act_version;
			fclose(fp);
		}
		version->minor = 0;
	}
	else{

		ret = tcs_get_policies_version(ver, &num);
		if(ret){
			httc_util_pr_error("tcs_get_policies_version error: %d(0x%x)\n", ret, ret);
				tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
			return ret;
		}
		for(; i < num; i++){
			if(version->type == ntohl(ver[i].be_policy)){
				act_version = ntohll(ver[i].be_version);
				if(version->type == POLICY_TYPE_FILE_INTEGRITY){
					version->major = get_major_version(act_version);
					ret = httc_get_file_integrity_subver(version->major,&version->minor);
					if(ret){
						httc_util_pr_error("httc_get_file_integrity_subver error %d\n",ret);
						return ret;
					}
				}else{
					version->major = act_version;
					version->minor = 0;
				}
			}
		}
	}

	tcf_util_sem_release (TCF_SEM_INDEX_POLICY);
	return TCF_SUCCESS;
}
