#ifndef  _POLICY_DMEASURE_H
#define  _POLICY_DMEASURE_H
#include <linux/skbuff.h>
//#include <net/sock.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/syscall.h>
#endif
#include <linux/kthread.h>
#include <linux/module.h>
#include "policy/feature_configure.h"

#define DMEASURE				1
#define NO_DMEASURE				0

#define SYSCALL_SUM				285
#define SYSCALL_NAME_LEN		32

#define MODULES_SUM				128

#define FILESYSTEM_NAME_LEN		64
#define FILESYSTEM_SUM			64

#define FAMILY_NAME_LEN			32
#define FAMILY_SUM				AF_MAX
#define PROTO_NAME_LEN			32
#define PROTO_SUM				64

/* kernel/idt/syscall  policy */
struct dm_switch_policy {
	int interval;		/* 1 = 1s */
	int status;
} __attribute__ ((packed));

/* modules policy */
struct mod_policy {
	int flag;
	char mod_name[MODULE_NAME_LEN];
} __attribute__ ((packed));

struct modules_policy {
	int interval;		/* 1 = 10s */
	int status;
	struct mod_policy mp[MODULES_SUM];
} __attribute__ ((packed));

/* filesystem policy */
struct fs_policy {
	int flag;
	char fs_name[FILESYSTEM_NAME_LEN];
} __attribute__ ((packed));

struct filesystem_policy {
	int interval;		/* 1 = 10s */
	int status;
	struct fs_policy fsp[FILESYSTEM_SUM];
} __attribute__ ((packed));

/* net policy */
struct proto_policy {
	int flag;
	char p_name[PROTO_NAME_LEN];
} __attribute__ ((packed));

struct family_policy {
	int flag;
	char f_name[FAMILY_NAME_LEN];
} __attribute__ ((packed));

struct net_policy {
	int interval;		/* 1 = 10s */
	int status;
	struct family_policy fp[FAMILY_SUM];
	struct proto_policy pp[PROTO_SUM];
} __attribute__ ((packed));

struct dmeasure_feature_conf {
	uint32_t is_enabled;       //be_dynamic_measure_on
	uint32_t measure_mode;     // 0 - soft; 1 - tpcm
	uint32_t time_interval;    //be_process_dmeasure_interval
	uint32_t is_lib_measure;   //be_process_dmeasure_lib_mode
	uint32_t is_child_measure; //be_process_dmeasure_sub_process_mode
	uint32_t is_exsited_process_measure; //be_process_dmeasure_old_process_mode
};

/* process policy */
struct process_policy {
	struct list_head list;
	atomic_t obj_count; //引用计数
	int process_switch; //0关闭 1打开
	//int interval_count;
	int object_id_type;//客体标识类型全路径、进程名、HASH
	int sub_process_mode;//子进程，度量、不度量、默认（按全局策略控制）
	int old_process_mode;//策略生效前已启动的进程，度量、不度量、默认（按全局策略控制）
	int share_lib_mode; //共享库，度量、不度量、默认（按全局策略控制）
	int be_measure_interval;//度量间隔毫秒，0为默认（按全局策略控制）
	int be_object_id_length; //客体长度
	unsigned char object_id[0]; //客体标识（全路径、进程名、HASH）
	//char *full_path;
	//char *process_name;
	//char *hash;
} __attribute__ ((packed));

struct processes_policy {
	int interval;		/* 1 = 10s */
	int status;
	struct list_head head;
} __attribute__ ((packed));
/* end */

int ksection_policy_add(struct dm_switch_policy *policy);
//int ksection_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);
int idt_policy_add(struct dm_switch_policy *policy);
//int idt_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);
int syscall_policy_add(struct dm_switch_policy *policy);
//int syscall_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);
int modules_policy_add(struct dm_switch_policy *policy);
//int modules_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);
int filesystem_policy_add(struct dm_switch_policy *policy);
//int filesystem_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);
int net_policy_add(struct dm_switch_policy *policy);
//int net_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh);

//int get_modules_policy(struct modules_policy *modules);
//int get_filesystem_policy(struct filesystem_policy *filesystem);
//int get_net_policy(struct net_policy *netpolicy);

struct process_policy *query_policy_dmeasure_process(char *full_path, char* process_name, char *hash, int hash_len);

int dmeasure_policy_init(void);
void dmeasure_policy_exit(void);

int policy_is_empty(void);
struct dmeasure_feature_conf *get_dmeasure_feature_conf(void);

#endif
