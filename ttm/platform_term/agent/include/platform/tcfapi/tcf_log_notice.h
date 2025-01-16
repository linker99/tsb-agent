#ifndef TCFAPI_TCF_LOG_NOTICE_H_
#define TCFAPI_TCF_LOG_NOTICE_H_
#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
#include "../tcsapi/tcs_notice.h"
#include "../tsbapi/tsb_admin.h"


/** ����������־���� */
enum{
	LOG_TNC_NEGOTIATION_OK = 1,//Э�̳ɹ����ɲ������־��
	LOG_TNC_NEGOTIATION_FAIL,//Э��ʧ��
	LOG_TNC_CREATE_SESSION,//�����Ự֪ͨ
	LOG_TNC_CREATE_DELETE,//(����)ɾ���Ự֪ͨ
	LOG_TNC_SESSION_EXPIRE_ALL,//�Ự����֪ͨ(����ɾ��)
	LOG_TNC_SESSION_EXPIRE_HALF//�Ự�������֪ͨ(˫��䵥��)
};

#pragma pack(push, 1)
struct log{
	unsigned int magic;
	unsigned int type;
	unsigned int operate;
	unsigned int result;
	unsigned int userid;
	int pid;
	int repeat_num;
	long time;
	int total_len;
	int len_subject;
	int len_object;
	char sub_hash[DEFAULT_HASH_SIZE];
	char data[0];  //��������+������
};

struct tnc_create_session_notice{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint64_t be_expire_time;
	uint32_t be_peer_addr;
	uint32_t be_is_bi_direction;
};

struct session_expire_notice_half{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint64_t be_next_expire_time;
	uint32_t be_peer_addr;
};

struct session_expire_or_delete_notice{
	uint64_t be_local_session_id;
	uint64_t be_peer_session_id;
	uint64_t be_time;
	uint32_t be_peer_addr;
};

/** ����Э��֪ͨ */
struct tnc_disagreement_notice{
	uint64_t be_time;
	uint32_t be_peer_addr;
};

/** ����������־ */
struct tnc_log{
	uint32_t action;
	uint32_t peer_addr;//Э�̺ͻỰ�����־��д
	uint64_t local_session_id;//�Ự�����־��д
	uint64_t peer_session_id;//�Ự�����־��д
	uint64_t expire_time;//�����Ựʱ��д
	uint32_t is_bi_direction;//�����Ựʱ��д
	uint32_t error_code;//Э��ʧ��ʱ��д��������0
};
#pragma pack(pop)

/*
 * ������ʽ��ȡ��־
 */
int tcf_read_logs(struct log ***logs, int *num_inout, unsigned int timeout);

/*
 * ��������ʽ��ȡ��־
 */
int tcf_read_logs_noblock(struct log ***logs, int *num_inout);
/*
 * ɾ����־
 */
int tcf_remove_logs(struct log *log);
/*
 * �ͷŶ�ȡ��־���ڴ�ռ�
 */
int tcf_free_logs(int num,struct log **logs);

/** д����־ */
int tcf_write_logs (const char * data, int length);
/*
 * ɾ��������־
 */
int tcf_clear_all_logs();

/*
 * ����֪ͨ��ȡ����
 */
int tcf_create_notice_read_queue(void);

/*
 * �ر�֪ͨ��ȡ����
 */
void tcf_close_notice_read_queue(int fd);

/*
 * 	д���ڴ�֪ͨ��
 */
int tcf_write_notices(unsigned char *buffer, int length, int type);

/*
 * 	������ʽ��ȡ�ڴ�֪ͨ��
 */
int tcf_read_notices(int fd, struct notify **ppnode, int *num, unsigned int timeout);

/*
 * 	��������ʽ��ȡ�ڴ�֪ͨ��
 */
int tcf_read_notices_noblock(int fd, struct notify **ppnode, int *num);


#endif /* TCFAPI_TCF_LOG_NOTICE_H_ */
