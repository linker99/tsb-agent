#ifndef TRUNK_INCLUDE_TCFAPI_TCF_NETWORK_CONTROL_H_
#define TRUNK_INCLUDE_TCFAPI_TCF_NETWORK_CONTROL_H_

#include <stdint.h>
#include "../tcsapi/tcs_constant.h"
//#include "../tcsapi/tcs_network_control_def.h"



struct network_control_update;


#define NET_CONF_BLACK_FLAGS  0x00000001  /* 黑名单标记 */
#define NET_CONF_PORT_FLAGS   0x00000002  /* 端口标记 */
#define NET_CONF_TCP_FLAGS    0x00000004  /* TCP标记 */
#define NET_CONF_UDP_FLAGS    0x00000008  /* UDP标记 */

 struct ip_config_user
{
	uint32_t id;        /* 用户配置ID */
	uint32_t from;      /* 用户开始端口或IP */
	uint32_t to;        /* 用户结束端口或IP */ 
	uint32_t status;     /* 0bit--黑白名单标记位; 1bit--端口策略; 2bit--TCP标记; 3bit--UDP标记 */
};

 struct network_config_item_user
{
	uint32_t port_sw;       /* 网络过滤开关 0--关闭 1--打开 */
	uint32_t total_num;     /* 配置策略总数 */
	struct ip_config_user **item;
};

/*
 * 	��ȡ������������
 */
int tcf_get_network_control_policy(struct network_config_item_user **references, unsigned int *inout_num);//proc ����


/*
 * 	���¹�����������
 * 	֧�����á�
 */


int tcf_update_network_control_policy(
		struct network_control_update *references,
		const char *uid,int cert_type,
		unsigned int auth_length,unsigned char *auth);
/**/
int tcf_prepare_update_network_control_policy(
		struct network_config_item_user *items,unsigned int num,
		unsigned char *tpcm_id,unsigned int tpcm_id_length,
		int action,uint64_t replay_counter,
		struct network_control_update **buffer,unsigned int *prepare_size);

/*释放*/

void tcf_free_network_control_policy(struct network_config_item_user * pp,unsigned int num);	
#endif /* TRUNK_INCLUDE_TCFAPI_TCF_DEV_PROTECT_H_ */
