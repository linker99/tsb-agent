/*
 * tsb_tnc_session.h
 *
 *  Created on: 2021年6月28日
 *      Author: wangtao
 */

#ifndef SRC_USER_TSBAPI_TSB_TNC_SESSION_H_
#define SRC_USER_TSBAPI_TSB_TNC_SESSION_H_

#include <stdint.h>
#pragma pack(push, 1)
struct httc_net_session_user{

	uint64_t local_session_id;//本机会话ID
	uint64_t peer_session_id;//对端会话ID
	uint64_t expire_time;//会话过期时间，秒
	uint32_t be_peer_addr;//对端ID地址
	uint32_t is_bidir;//是否双向会话。NAT的外网机器会建立单向会话，其它都是双向

};

struct httc_net_sessions{
	uint64_t count;//in out
	struct httc_net_session_user sessions[0];
};
#pragma pack(pop)

int tsb_get_tnc_sessions(struct  httc_net_sessions **sessions);

int tsb_del_tnc_session(uint64_t local_session_id,uint64_t peer_session_id);


#endif /* SRC_USER_TSBAPI_TSB_TNC_SESSION_H_ */
