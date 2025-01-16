

#ifndef TCFAPI_TCF_ATTEST_H_
#define TCFAPI_TCF_ATTEST_H_
#include <stdint.h>

#include "../tcsapi/tcs_attest_def.h"

enum POLICY_SOURCE_ENUM{
	POLICY_SOURCE_HOST = 1, 	//终端
	POLICY_SOURCE_SOC,		//管理中心
	POLICY_SOURCE_MAX,
};

#pragma pack(push, 1)
struct policy_version_user{	
	uint64_t major;
	uint32_t minor;
	uint32_t type;
};
struct policy_source_user{	
	uint32_t source;
	uint32_t type;
};
#pragma pack(pop)

/*
 * 	生成可信证明
 */
int tcf_generate_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,uint8_t *attached_hash);

/*
 * 	验证远程可信证明
 */
int tcf_verify_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,unsigned char *oid);

/*
 * 	生成可信报告
 */
int tcf_generate_trust_report(struct trust_report *report,uint64_t nonce);

/*
 * 	验证可信报告
 */
int tcf_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid);

/*
 *	 获取本地可信状态
 */
int tcf_get_trust_status (uint32_t *status);

/*
 *	获取TPCM信息
 */
int tcf_get_tpcm_info(struct tpcm_info *status);//proc 导出

/*
 * 	获取TPCM ID
 */
int tcf_get_tpcm_id(unsigned char *id,int *len_inout);//proc 导出


/*
 * 	获取HOST ID
 */
int tcf_get_host_id(unsigned char *id,int *len_inout);//proc 导出

/*
 * 	设置HOST ID
 */
int tcf_set_host_id(unsigned char *id,int len);//proc 导出


/*
 * 	获取TPCM特性
 */

int tcf_get_tpcm_features(uint32_t *features);

/*
 * 	获取TPCM身份密钥公钥
 */
int tcf_get_pik_pubkey(unsigned char *pubkey,int *len_inout);


/*
 * 	生成TPCM身份密钥
 */
int tcf_generate_tpcm_pik(unsigned char *passwd);

/*
 * 	与对端进行远程证明
 */
int tcf_remote_attest(const char *peer);

/*
 * 	添加信任的远程证书
 */

int tcf_add_remote_cert(struct remote_cert *remote_cert);
/*
 * 	删除信任的远程证书
 */
int tcf_remove_remote_cert(const char *id);

/*
 * 	获取信任的远程证书列表
 * 	返回所有证书的数组
 */
int tcf_get_remote_certs(struct remote_cert **remote_cert,int *number);

/*
 * 	获取当前防重放计数
 */
int tcf_get_replay_counter (uint64_t *replay_counter);

/*
 * 获取策略版本列表(tpcm && tcm)
 */
int tcf_get_policies_version (struct policy_version_user *version, int *num_inout);

/*
 * 获取指定策略版本列表(tpcm策略)
 */
int tcf_get_one_policy_version (struct policy_version_user *version);


#endif /* TCFAPI_TCF_ATTEST_H_ */

