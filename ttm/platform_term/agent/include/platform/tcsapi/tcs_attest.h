
#ifndef TCSAPI_TCS_ATTEST_H_
#define TCSAPI_TCS_ATTEST_H_
#include <stdint.h>
#include "tcs_constant.h"
#include "tcs_policy.h"
#include "tcs_attest_def.h"

/*
 * 	���ɿ���֤��
 */
int tcs_generate_trust_evidence(struct trust_evidence *evidence,
		uint64_t nonce,	unsigned char *host_id, uint8_t *attached_hash);

/*
 * 	��֤Զ�̿���֤��
 */
int tcs_verify_trust_evidence(struct trust_evidence *evidence,
		uint64_t nonce,		unsigned char *oid);

/*
 * 	���ɿ��ű���
 */
int tcs_generate_trust_report(struct trust_report *report,
		uint64_t nonce,		unsigned char *host_id);

/*
 * 	��֤���ű���
 */
int tcs_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid);

/*
 *	 ��ȡ���ؿ���״̬
 */
int tcs_get_trust_status (uint32_t *status);

/*
 *	 ͬ������״̬
 */
int tcs_sync_trust_status (uint32_t type);


/*
 *	��ȡTPCM��Ϣ
 */
int tcs_get_tpcm_info(struct tpcm_info *info);//proc ����

/*
 * 	��ȡTPCM ID
 */
int tcs_get_tpcm_id(unsigned char *id,int *len_inout);//proc ����


/*
 * 	��ȡHOST ID
 */
int tcs_get_host_id(unsigned char *id,int *len_inout);

/*
 * 	����HOST ID
 */
int tcs_set_host_id(unsigned char *id,int len);

/*
 * 	��ȡTPCM����
 */

int tcs_get_tpcm_features(uint32_t *features);

/*
 * 	��ȡTPCM������Կ��Կ
 */
int tcs_get_pik_pubkey(unsigned char *pubkey,int *len_inout);


/*
 * 	����TPCM������Կ
 */
int tcs_generate_tpcm_pik(unsigned char *passwd);



/*
 * 	��Զ˽���Զ��֤��
 */
int tcs_remote_attest(const char *peer);

/*
 * 	�������ε�Զ��֤��
 */

int tcs_add_remote_cert(struct remote_cert *remote_cert);

/*
 * 	ɾ�����ε�Զ��֤��
 */
int tcs_remove_remote_cert(const char *id);

/*
 * 	��ȡ���ε�Զ��֤���б�
 * 	��������֤�������
 */
int tcs_get_remote_certs(struct remote_cert **remote_cert,int *number);

/*
 * 	��ȡ��ǰ���طż���
 */
int tcs_get_replay_counter (uint64_t *replay_counter);

/*
 * ��ȡ���԰汾�б�(tpcm����)
 * version : [��������(4�ֽ�) + �汾(8�ֽ�)] * num 
 */
int tcs_get_policies_version (struct policy_version *version, int *num_inout);

/*
 * ��ȡTpcm��־
 * 
 */

int tcs_get_tpcm_log (int *length, unsigned char *log);

#endif /* TCSAPI_TCS_ATTEST_H_ */

