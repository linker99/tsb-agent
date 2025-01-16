

#ifndef TCSAPI_TCS_ATTEST_H_
#define TCSAPI_TCS_ATTEST_H_
#include <stdint.h>
#include "tcs_constant.h"
#include "tcs_policy.h"
#include "tcs_attest_def.h"

/*
 * 	生成可信证明
 */
int tcs_generate_trust_evidence(struct trust_evidence *evidence,
		uint64_t nonce,	unsigned char *host_id, uint8_t *attached_hash);

/*
 * 	验证远程可信证明
 */
int tcs_verify_trust_evidence(struct trust_evidence *evidence,
		uint64_t nonce,		unsigned char *oid);

/*
 * 	生成可信报告
 */
int tcs_generate_trust_report(struct trust_report *report,
		uint64_t nonce,		unsigned char *host_id);

/*
 * 	验证可信报告
 */
int tcs_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid);

/*
 *	 获取本地可信状态
 */
int tcs_get_trust_status (uint32_t *status);

/*
 *	获取TPCM信息
 */
int tcs_get_tpcm_info(struct tpcm_info *info);//proc 导出

/*
 * 	获取TPCM ID
 */
int tcs_get_tpcm_id(unsigned char *id,int *len_inout);//proc 导出

int tcs_get_host_id(unsigned char *id,int *len_inout);

/*
 * 	获取TPCM特性
 */

int tcs_get_tpcm_features(uint32_t *features);

/*
 * 	获取TPCM身份密钥公钥
 */
int tcs_get_pik_pubkey(unsigned char *pubkey,int *len_inout);


/*
 * 	生成TPCM身份密钥
 */
int tcs_generate_tpcm_pik(unsigned char *passwd);



/*
 * 	与对端进行远程证明
 */
int tcs_remote_attest(const char *peer);

/*
 * 	添加信任的远程证书
 */

int tcs_add_remote_cert(struct remote_cert *remote_cert);

/*
 * 	删除信任的远程证书
 */
int tcs_remove_remote_cert(const char *id);

/*
 * 	获取信任的远程证书列表
 * 	返回所有证书的数组
 */
int tcs_get_remote_certs(struct remote_cert **remote_cert,int *number);

/*
 * 	获取当前防重放计数
 */
int tcs_get_replay_counter (uint64_t *replay_counter);

#endif /* TCSAPI_TCS_ATTEST_H_ */
