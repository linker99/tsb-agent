/*
 * attest.h
 *
 *  Created on: 2021年1月22日
 *      Author: wangtao
 */

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

/*获取瑞达ip*/
int tcs_get_ruida_ip(uint32_t *hostip, uint32_t *num);
/*
 * 	生成可信报告
 */
int tcs_generate_trust_report(struct trust_report *report,
		uint64_t nonce,		unsigned char *host_id,uint32_t be_addr);

/*
 * 	验证可信报告
 */
int tcs_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid);

/*
 *	 获取本地可信状态
 */
int tcs_get_trust_status (uint32_t *status);


/*
 *	 ͬ同步可信状态
 */
int tcs_sync_trust_status (uint32_t type);



/*
 *	获取TPCM信息
 */
int tcs_get_tpcm_info(struct tpcm_info *info);

/*
 *	获取驱动类型信息
 */
int tcs_get_tdd_info(struct tdd_info *info);

/*
 * 	获取TPCM ID
 */
int tcs_get_tpcm_id(unsigned char *id,int *len_inout);

/*
 * 	获取HOST ID
 */
int tcs_get_host_id(unsigned char *id,int *len_inout);

/*
 * 	设置HOST ID
 */
int tcs_set_host_id(unsigned char *id,int len);

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

/*
 * 获取策略版本列表(tpcm策略)
 * version : [策略名称(4字节) + 版本(8字节)] * num
 */
int tcs_get_policies_version (struct policy_version *version, int *num_inout);

/*
 * 获取Tpcm日志
 *
 */

int tcs_get_tpcm_log (int *length, unsigned char *log);

#endif /* TCSAPI_TCS_ATTEST_H_ */

