
#ifndef SRC_USER_TSBAPI_TSB_TNC_SESSION_H_
#define SRC_USER_TSBAPI_TSB_TNC_SESSION_H_

#include <stdint.h>
#pragma pack(push, 1)
struct httc_net_session_user{

	uint64_t local_session_id;//�����ỰID
	uint64_t peer_session_id;//�Զ˻ỰID
	uint64_t expire_time;//�Ự����ʱ�䣬��
	uint32_t be_peer_addr;//�Զ�ID��ַ
	uint32_t is_bidir;//�Ƿ�˫��Ự��NAT�����������Ὠ������Ự����������˫��

};

struct httc_net_sessions{
	uint64_t count;//in out
	struct httc_net_session_user sessions[0];
};
#pragma pack(pop)

int tsb_get_tnc_sessions(struct  httc_net_sessions **sessions);

int tsb_del_tnc_session(uint64_t local_session_id,uint64_t peer_session_id);


#endif /* SRC_USER_TSBAPI_TSB_TNC_SESSION_H_ */
