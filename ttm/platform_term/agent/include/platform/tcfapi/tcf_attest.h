#ifndef TCFAPI_TCF_ATTEST_H_
#define TCFAPI_TCF_ATTEST_H_
#include <stdint.h>

#include "../tcsapi/tcs_attest_def.h"

enum POLICY_SOURCE_ENUM{
	POLICY_SOURCE_HOST = 1, 	//�ն�
	POLICY_SOURCE_SOC,		//��������
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
 * 	���ɿ���֤��
 */
int tcf_generate_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,uint8_t *attached_hash);

/*
 * 	��֤Զ�̿���֤��
 */
int tcf_verify_trust_evidence(struct trust_evidence *evidence,uint64_t nonce,unsigned char *oid);

/*
 * 	���ɿ��ű���
 */
int tcf_generate_trust_report(struct trust_report *report,uint64_t nonce, int32_t ip);

/*
 * 	��֤���ű���
 */
int tcf_verify_trust_report(struct trust_report *report,uint64_t nonce,unsigned char *oid);

/*
 *	 ��ȡ���ؿ���״̬
 */
int tcf_get_trust_status (uint32_t *status);

/*
 *	��ȡTPCM��Ϣ
 */
int tcf_get_tpcm_info(struct tpcm_info *status);//proc ����

/*
 * 	��ȡTPCM ID
 */
int tcf_get_tpcm_id(unsigned char *id,int *len_inout);//proc ����


/*
 * 	��ȡHOST ID
 */
int tcf_get_host_id(unsigned char *id,int *len_inout);//proc ����

/*
 * 	����HOST ID
 */
int tcf_set_host_id(unsigned char *id,int len);//proc ����


/*
 * 	��ȡTPCM����
 */

int tcf_get_tpcm_features(uint32_t *features);

/*
 * 	��ȡTPCM������Կ��Կ
 */
int tcf_get_pik_pubkey(unsigned char *pubkey,int *len_inout);


/*
 * 	����TPCM������Կ
 */
int tcf_generate_tpcm_pik(unsigned char *passwd);

/*
 * 	��Զ˽���Զ��֤��
 */
int tcf_remote_attest(const char *peer);

/*
 * 	�������ε�Զ��֤��
 */

int tcf_add_remote_cert(struct remote_cert *remote_cert);
/*
 * 	ɾ�����ε�Զ��֤��
 */
int tcf_remove_remote_cert(const char *id);

/*
 * 	��ȡ���ε�Զ��֤���б�
 * 	��������֤�������
 */
int tcf_get_remote_certs(struct remote_cert **remote_cert,int *number);

/*
 * 	��ȡ��ǰ���طż���
 */
int tcf_get_replay_counter (uint64_t *replay_counter);

/*
 * ��ȡ���԰汾�б�(tpcm && tcm)
 */
int tcf_get_policies_version (struct policy_version_user *version, int *num_inout);

/*
 * ��ȡָ�����԰汾�б�(tpcm����)
 */
int tcf_get_one_policy_version (struct policy_version_user *version);


#endif /* TCFAPI_TCF_ATTEST_H_ */

