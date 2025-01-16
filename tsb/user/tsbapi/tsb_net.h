#ifndef TSB_NET_H_
#define TSB_NET_H_

#define NET_CONF_BLACK_FLAGS  0x00000001  /* 黑名单标记 */
#define NET_CONF_PORT_FLAGS   0x00000002  /* 端口标记 */
#define NET_CONF_TCP_FLAGS    0x00000004  /* TCP标记 */
#define NET_CONF_UDP_FLAGS    0x00000008  /* UDP标记 */

typedef struct __ip_config
{
	uint32_t id;         /* 用户配置ID */
	uint32_t from;       /* 用户开姿«¯口或IP */
	uint32_t to;         /* 用户结束端口或IP */
	uint32_t flags;     /* 0bit--黑白名单标记使 1bit--端口策略; 2bit--TCP标记; 3bit--UDP标记 */
}__attribute__((packed)) ip_config;

typedef struct network_config
{
	uint32_t main_sw;      /* 网络控制开关 0--关闿1--打开 */
	uint32_t total_num;     /* 配置策略总数 */
	ip_config item[0];
}__attribute__((packed)) NET_RANGE;

int tsb_reload_network(void);
int tsb_clear_filter_list(void);

typedef struct __net_audit_data
{
	uint32_t srcIp;          /* 源IP */
	uint32_t destIp;         /* 目标IP */
	uint16_t srcPort;      /* 源端口 */
	uint16_t destPort;     /* 目标端口 */
	uint8_t protocol;      /* 引用<linux/in.h>中的枚举定义 */
	uint8_t action;                 /*  审计结果1: denied, 2: pass */
	uint8_t direction;              /* 方向1: out,  0: in  */
}__attribute__((packed))  net_audit_data;

int tsb_reload_network(void);
int tsb_clear_filter_list(void);

#endif /* TSB_NET_H_ */
