#include <linux/version.h>
#include "policy_dmeasure.h"
//#include "policy_data.h"
#include "../dmeasure/dmeasure.h"
#include "utils/debug.h"
#include "msg/command.h"
//#include "tcsapi/tcs_dmeasure.h"
#include "tpcm_def.h"
#include "common.h"
#include "tpcm/tpcmif.h"
#include "tsbapi/tsb_measure_kernel.h"
//#include "policy/global_policy.h"

extern struct sock *ker_sock;
extern struct mutex policy_cmd_mutex;



struct policy_ksection {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_idt {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_syscall {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_modules {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_filesystem {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_net {
	rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct dm_switch_policy policy;
} __attribute__ ((packed));

struct policy_process {
	//rwlock_t t_lock;
	int original_interval;
	int original_status;
	struct processes_policy policy;
} __attribute__ ((packed));

struct policy_syscall *syscall_p = NULL;
struct policy_modules *modules_po = NULL;
struct policy_filesystem *filesystem_po = NULL;
struct policy_net *net_po = NULL;
struct policy_ksection *ksection_p = NULL;
struct policy_idt *idt_p = NULL;

struct policy_process *p_process = NULL;
rwlock_t g_policy_dmeasure_process_lock;

static struct dmeasure_feature_conf dmeasure_feature;

void ksection_policy_exit(void)
{
	if (ksection_p) {
		kfree(ksection_p);
		ksection_p = NULL;
	}
}

int ksection_policy_init(void)
{
	int ret = 0;

	ksection_p = kzalloc(sizeof(struct policy_ksection), GFP_KERNEL);
	if (!ksection_p) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc ksection policy err!\n");
		ret = -ENOMEM;
		goto err;
	}

	ksection_p->original_interval = ksection_p->policy.interval = 0;
	ksection_p->original_status = ksection_p->policy.status =
		ACTION_STATUS_DISABLED;
	rwlock_init(&ksection_p->t_lock);

err:
	return ret;
}

int ksection_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	int interval, original_interval, status, original_status;
	//struct policy_data *data = NULL;
	//struct dm_switch_policy *policy = NULL;

	//data = (struct policy_data *)NLMSG_DATA(nlh);
	//ret = check_policy_valid(skb, nlh, data);
	//if (ret < 0) {
	//	return ret;
	//}

	if (!ksection_p)
		return -EINVAL;

	//policy = (struct dm_switch_policy *)data->data;
	//len = sizeof(struct dm_switch_policy);

	write_lock(&ksection_p->t_lock);
	memset(&ksection_p->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&ksection_p->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = ksection_p->original_interval;
	original_status = ksection_p->original_status;
	interval = ksection_p->policy.interval;
	status = ksection_p->policy.status;
	ksection_p->original_interval = ksection_p->policy.interval;
	ksection_p->original_status = ksection_p->policy.status;
	write_unlock(&ksection_p->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_KSECTION_NAME);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set ksection policy interval:[%d], status:[%d]!\n",
		  ksection_p->policy.interval, ksection_p->policy.status);

	return ret;
}

void idt_policy_exit(void)
{
	if (idt_p) {
		kfree(idt_p);
		idt_p = NULL;
	}
}

int idt_policy_init(void)
{
	int ret = 0;

	idt_p = kzalloc(sizeof(struct policy_idt), GFP_KERNEL);
	if (!idt_p) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc idt policy err!\n");
		ret = -ENOMEM;
		goto err;
	}

	idt_p->original_interval = idt_p->policy.interval = 0;
	idt_p->original_status = idt_p->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&idt_p->t_lock);

err:
	return ret;
}

int idt_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	//int len = 0;
	int interval, original_interval, status, original_status;
	//struct policy_data *data = NULL;
	//struct dm_switch_policy *policy = NULL;

	//data = (struct policy_data *)NLMSG_DATA(nlh);
	//ret = check_policy_valid(skb, nlh, data);
	//if (ret < 0) {
	//	return ret;
	//}

	if (!idt_p)
		return -EINVAL;

	//policy = (struct dm_switch_policy *)data->data;
	//len = sizeof(struct dm_switch_policy);

	write_lock(&idt_p->t_lock);
	memset(&idt_p->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&idt_p->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = idt_p->original_interval;
	original_status = idt_p->original_status;
	interval = idt_p->policy.interval;
	status = idt_p->policy.status;
	idt_p->original_interval = idt_p->policy.interval;
	idt_p->original_status = idt_p->policy.status;
	write_unlock(&idt_p->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_IDTTABLE_NAME);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set idt policy interval:[%d], status:[%d]!\n",
		  idt_p->policy.interval, idt_p->policy.status);

	return ret;
}

void syscall_policy_exit(void)
{
	if (syscall_p) {
		kfree(syscall_p);
		syscall_p = NULL;
	}
}

int syscall_policy_init(void)
{
	int ret = 0;

	syscall_p = kzalloc(sizeof(struct policy_syscall), GFP_KERNEL);
	if (!syscall_p) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc syscall policy err!\n");
		ret = -ENOMEM;
		goto err;
	}

	syscall_p->original_interval = syscall_p->policy.interval = 0;
	syscall_p->original_status = syscall_p->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&syscall_p->t_lock);

err:
	return ret;
}

int syscall_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	//int len = 0;
	int interval, original_interval, status, original_status;
	//struct policy_data *data = NULL;
	//struct dm_switch_policy *policy = NULL;

	//data = (struct policy_data *)NLMSG_DATA(nlh);
	//ret = check_policy_valid(skb, nlh, data);
	//if (ret < 0) {
	//	return ret;
	//}

	if (!syscall_p)
		return -EINVAL;

	//policy = (struct dm_switch_policy *)data->data;
	//len = sizeof(struct dm_switch_policy);

	write_lock(&syscall_p->t_lock);
	memset(&syscall_p->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&syscall_p->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = syscall_p->original_interval;
	original_status = syscall_p->original_status;
	interval = syscall_p->policy.interval;
	status = syscall_p->policy.status;
	syscall_p->original_interval = syscall_p->policy.interval;
	syscall_p->original_status = syscall_p->policy.status;
	write_unlock(&syscall_p->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_SYSCALLTABLE_NAME);
	}

	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set syscall policy interval:[%d], status:[%d]!\n",
		  syscall_p->policy.interval, syscall_p->policy.status);

	return ret;
}

//int get_modules_policy(struct modules_policy *modules)
//{
//	int ret = 0;
//	int len = sizeof(struct modules_policy);
//
//	read_lock(&modules_po->t_lock);
//	memcpy(modules, &modules_po->policy, len);
//	read_unlock(&modules_po->t_lock);
//
//	return ret;
//}
//
//EXPORT_SYMBOL(get_modules_policy);

//int modules_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh)
//{
//	int ret = 0;
//	int len = 0;
//	struct modules_policy *policy = NULL;
//	u32 seq;
//
//	len = sizeof(struct modules_policy);
//	seq = nlh->nlmsg_seq;
//
//	policy = kzalloc(len, GFP_KERNEL);
//	if (!policy) {
//		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc modules policy err!\n");
//		ret = -ENOMEM;
//		goto err;
//	}
//
//	read_lock(&modules_po->t_lock);
//	memcpy(policy, &modules_po->policy, len);
//	read_unlock(&modules_po->t_lock);
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
//	syscall_send_reply(NETLINK_CB(skb).portid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#else
//	syscall_send_reply(NETLINK_CB(skb).pid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#endif
//
//	kfree(policy);
//err:
//	return ret;
//}

int modules_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	//int i = 0;
	//int len = 0;
	int interval, original_interval, status, original_status;
	//struct modules_policy *policy = NULL;

	//len = sizeof(struct modules_policy);

	//if (nlh->nlmsg_len != NLMSG_SPACE(len)) {
	//	DEBUG_MSG(HTTC_TSB_INFO,
	//		  "Enter:[%s], recv modules policy err, nlmsg_len:[%d], policy:[%u]!\n",
	//		  __func__, nlh->nlmsg_len, NLMSG_SPACE(len));
	//	return -EINVAL;
	//}

	if (!modules_po)
		return -EINVAL;

	//policy = (struct modules_policy *)NLMSG_DATA(nlh);
	write_lock(&modules_po->t_lock);
	memset(&modules_po->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&modules_po->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = modules_po->original_interval;
	original_status = modules_po->original_status;
	interval = modules_po->policy.interval;
	status = modules_po->policy.status;
	modules_po->original_interval = modules_po->policy.interval;
	modules_po->original_status = modules_po->policy.status;
	write_unlock(&modules_po->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_MODULELIST_NAME);
	}

	//for (i = 0; i < MODULES_SUM; i++) {
	//	if (modules_po->policy.mp[i].flag == DMEASURE)
	//		DEBUG_MSG(HTTC_TSB_DEBUG, "set module:[%s] policy!\n",
	//			  modules_po->policy.mp[i].mod_name);
	//}
	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set modules policy interval:[%d], status:[%d]!\n",
		  modules_po->policy.interval, modules_po->policy.status);

	return ret;
}

int modules_policy_init(void)
{
	int ret = 0;
	//int i = 0;

	modules_po = kzalloc(sizeof(struct policy_modules), GFP_KERNEL);
	if (!modules_po) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc modules policy err!\n");
		ret = -ENOMEM;
		goto err;
	}
	//default modules policy
	//for (i = 0; i < MODULES_SUM; i++) {
	//	modules_po->policy.mp[i].flag = NO_DMEASURE;
	//	memset(modules_po->policy.mp[i].mod_name, 0, MODULE_NAME_LEN);
	//}
	modules_po->original_interval = modules_po->policy.interval = 0;
	modules_po->original_status = modules_po->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&modules_po->t_lock);

err:
	return ret;
}

void modules_policy_exit(void)
{
	if (modules_po) {
		kfree(modules_po);
		modules_po = NULL;
	}
}

//int get_filesystem_policy(struct filesystem_policy *filesystem)
//{
//	int ret = 0;
//	int len = sizeof(struct filesystem_policy);
//
//	read_lock(&filesystem_po->t_lock);
//	memcpy(filesystem, &filesystem_po->policy, len);
//	read_unlock(&filesystem_po->t_lock);
//
//	return ret;
//}
//
//EXPORT_SYMBOL(get_filesystem_policy);
//
//int filesystem_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh)
//{
//	int ret = 0;
//	int len = 0;
//	struct filesystem_policy *policy = NULL;
//	u32 seq;
//
//	len = sizeof(struct filesystem_policy);
//	seq = nlh->nlmsg_seq;
//
//	policy = kzalloc(len, GFP_KERNEL);
//	if (!policy) {
//		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc filesystem policy err!\n");
//		ret = -ENOMEM;
//		goto err;
//	}
//
//	read_lock(&filesystem_po->t_lock);
//	memcpy(policy, &filesystem_po->policy, len);
//	read_unlock(&filesystem_po->t_lock);
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
//	syscall_send_reply(NETLINK_CB(skb).portid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#else
//	syscall_send_reply(NETLINK_CB(skb).pid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#endif
//
//	kfree(policy);
//err:
//	return ret;
//}

int filesystem_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	//int i = 0;
	//int len = 0;
	int interval, original_interval, status, original_status;
	//struct filesystem_policy *policy = NULL;

	//len = sizeof(struct filesystem_policy);

	//if (nlh->nlmsg_len != NLMSG_SPACE(len)) {
	//	DEBUG_MSG(HTTC_TSB_INFO,
	//		  "Enter:[%s], recv filesystem policy err, nlmsg_len:[%d], policy:[%u]!\n",
	//		  __func__, nlh->nlmsg_len, NLMSG_SPACE(len));
	//	return -EINVAL;
	//}

	if (!filesystem_po)
		return -EINVAL;

	//policy = (struct filesystem_policy *)NLMSG_DATA(nlh);
	write_lock(&filesystem_po->t_lock);
	memset(&filesystem_po->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&filesystem_po->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = filesystem_po->original_interval;
	original_status = filesystem_po->original_status;
	interval = filesystem_po->policy.interval;
	status = filesystem_po->policy.status;
	filesystem_po->original_interval = filesystem_po->policy.interval;
	filesystem_po->original_status = filesystem_po->policy.status;
	write_unlock(&filesystem_po->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_FILESYSTEM_NAME);
	}

	//for (i = 0; i < FILESYSTEM_SUM; i++) {
	//	if (filesystem_po->policy.fsp[i].flag == DMEASURE)
	//		DEBUG_MSG(HTTC_TSB_DEBUG,
	//			  "set filesystem:[%s] policy!\n",
	//			  filesystem_po->policy.fsp[i].fs_name);
	//}
	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set filesystem policy interval:[%d], status:[%d]!\n",
		  filesystem_po->policy.interval, filesystem_po->policy.status);

	return ret;
}

int filesystem_policy_init(void)
{
	int ret = 0;
	//int i = 0;

	filesystem_po = kzalloc(sizeof(struct policy_filesystem), GFP_KERNEL);
	if (!filesystem_po) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc filesystem policy err!\n");
		ret = -ENOMEM;
		goto err;
	}
	//default filesystem policy
	//for (i = 0; i < FILESYSTEM_SUM; i++) {
	//	filesystem_po->policy.fsp[i].flag = NO_DMEASURE;
	//	memset(filesystem_po->policy.fsp[i].fs_name, 0, FILESYSTEM_NAME_LEN);
	//}
	filesystem_po->original_interval = filesystem_po->policy.interval = 0;
	filesystem_po->original_status = filesystem_po->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&filesystem_po->t_lock);

err:
	return ret;
}

void filesystem_policy_exit(void)
{
	if (filesystem_po) {
		kfree(filesystem_po);
		filesystem_po = NULL;
	}
}

//int get_net_policy(struct net_policy *netpolicy)
//{
//	int ret = 0;
//	int len = sizeof(struct net_policy);
//
//	read_lock(&net_po->t_lock);
//	memcpy(netpolicy, &net_po->policy, len);
//	read_unlock(&net_po->t_lock);
//
//	return ret;
//}
//
//EXPORT_SYMBOL(get_net_policy);
//
//int net_policy_que(struct sk_buff *skb, struct nlmsghdr *nlh)
//{
//	int ret = 0;
//	int len = 0;
//	struct net_policy *policy = NULL;
//	u32 seq;
//
//	len = sizeof(struct net_policy);
//	seq = nlh->nlmsg_seq;
//
//	policy = kzalloc(len, GFP_KERNEL);
//	if (!policy) {
//		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc net policy err!\n");
//		ret = -ENOMEM;
//		goto err;
//	}
//
//	read_lock(&net_po->t_lock);
//	memcpy(policy, &net_po->policy, len);
//	read_unlock(&net_po->t_lock);
//
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
//	syscall_send_reply(NETLINK_CB(skb).portid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#else
//	syscall_send_reply(NETLINK_CB(skb).pid,
//			   seq, SECZONE_ACTIVE_QUERY, 1, 0, policy, len);
//#endif
//
//	kfree(policy);
//err:
//	return ret;
//}

int net_policy_add(struct dm_switch_policy *policy)
{
	int ret = 0;
	//int i = 0;
	//int len = 0;
	int interval, original_interval, status, original_status;
	//struct net_policy *policy = NULL;

	//len = sizeof(struct net_policy);

	//if (nlh->nlmsg_len != NLMSG_SPACE(len)) {
	//	DEBUG_MSG(HTTC_TSB_INFO,
	//		  "Enter:[%s], recv net policy err, nlmsg_len:[%d], policy:[%u]!\n",
	//		  __func__, nlh->nlmsg_len, NLMSG_SPACE(len));
	//	return -EINVAL;
	//}

	if (!net_po)
		return -EINVAL;

	//policy = (struct net_policy *)NLMSG_DATA(nlh);
	write_lock(&net_po->t_lock);
	memset(&net_po->policy, 0, sizeof(struct dm_switch_policy));
	memcpy(&net_po->policy, policy, sizeof(struct dm_switch_policy));
	original_interval = net_po->original_interval;
	original_status = net_po->original_status;
	interval = net_po->policy.interval;
	status = net_po->policy.status;
	net_po->original_interval = net_po->policy.interval;
	net_po->original_status = net_po->policy.status;
	write_unlock(&net_po->t_lock);

	if (original_interval != interval || original_status != status) {
		modify_dmeasure_action(interval, status, DM_ACTION_NETWORK_NAME);
	}

	//for (i = 0; i < FAMILY_SUM; i++) {
	//	if (net_po->policy.fp[i].flag == DMEASURE)
	//		DEBUG_MSG(HTTC_TSB_DEBUG,
	//			  "set net family:[%s] policy!\n",
	//			  net_po->policy.fp[i].f_name);
	//}

	//for (i = 0; i < PROTO_SUM; i++) {
	//	if (net_po->policy.pp[i].flag == DMEASURE)
	//		DEBUG_MSG(HTTC_TSB_DEBUG,
	//			  "set net proto:[%s] policy!\n",
	//			  net_po->policy.pp[i].p_name);
	//}

	DEBUG_MSG(HTTC_TSB_DEBUG,
		  "set net policy interval:[%d], status:[%d]!\n",
		  net_po->policy.interval, net_po->policy.status);

	return ret;
}

int net_policy_init(void)
{
	int ret = 0;
	//int i = 0;

	net_po = kzalloc(sizeof(struct policy_net), GFP_KERNEL);
	if (!net_po) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc net policy err!\n");
		ret = -ENOMEM;
		goto err;
	}
	////default net family policy
	//for (i = 0; i < FAMILY_SUM; i++) {
	//	net_po->policy.fp[i].flag = NO_DMEASURE;
	//	memset(net_po->policy.fp[i].f_name, 0, FAMILY_NAME_LEN);
	//}

	////default net proto policy
	//for (i = 0; i < PROTO_SUM; i++) {
	//	net_po->policy.pp[i].flag = NO_DMEASURE;
	//	memset(net_po->policy.pp[i].p_name, 0, FAMILY_NAME_LEN);
	//}

	net_po->original_interval = net_po->policy.interval = 0;
	net_po->original_status = net_po->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&net_po->t_lock);

err:
	return ret;
}

void net_policy_exit(void)
{
	if (net_po) {
		kfree(net_po);
		net_po = NULL;
	}
}

int process_policy_init(void)
{
	int ret = 0;

	p_process = kzalloc(sizeof(struct policy_process), GFP_KERNEL);
	if (!p_process) {
		DEBUG_MSG(HTTC_TSB_INFO, "kzalloc process policy err!\n");
		ret = -ENOMEM;
		goto err;
	}
	//default process policy
	INIT_LIST_HEAD(&p_process->policy.head);
	p_process->original_interval = p_process->policy.interval = 0;
	p_process->original_status = p_process->policy.status = ACTION_STATUS_DISABLED;
	rwlock_init(&g_policy_dmeasure_process_lock);

err:
	return ret;
}

void process_policy_exit(void)
{
	if (p_process) {

		struct list_head *pos = NULL, *tmp = NULL;

		write_lock(&g_policy_dmeasure_process_lock);
		list_for_each_safe(pos, tmp, &p_process->policy.head)
		{
			struct process_policy *p_process_policy  = list_entry(pos, struct process_policy, list);

			list_del(pos);
			kfree(p_process_policy);
		}

		kfree(p_process);
		p_process = NULL;

		write_unlock(&g_policy_dmeasure_process_lock);
	}
}

int policy_tcs_get_dmeasure_policy(void)
{
	struct dmeasure_policy_item *p_item = NULL, *p=NULL;
	int item_count=0, length=0, i=0, ret=0;

	ret = get_dmeasure_policy(&p, &item_count, &length);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], tcs_get_dmeasure_policy ret[%x] error!\n", __func__, ret);
		return -1;
	}
	
	p_item = p;
	for (i=0; i<item_count; i++)
	{
		struct dm_switch_policy dm_policy;
		dm_policy.status = 1;
		dm_policy.interval = NTOHL(p_item->be_interval_milli);

		if (strcmp(p_item->object, "syscall_table") == 0)
			syscall_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "kernel_section") == 0)
			ksection_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "idt_table") == 0)
			idt_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "module_list") == 0)
			modules_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "filesystem") == 0)
			filesystem_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "network") == 0)
			net_policy_add(&dm_policy);
		else
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure update policy name[%s] error!\n", __func__, p_item->object);

		p_item += 1;
	}
	vfree(p);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], tcs_get_dmeasure_policy item_count[%d] length[%d] success\n", __func__, item_count, length);

	return 0;
}

void close_dmeasure(void)
{
	struct dm_switch_policy dm_policy;

	dm_policy.interval = 0;
	dm_policy.status = ACTION_STATUS_DISABLED;

	syscall_policy_add(&dm_policy);
	ksection_policy_add(&dm_policy);
	idt_policy_add(&dm_policy);
	modules_policy_add(&dm_policy);
	filesystem_policy_add(&dm_policy);
	net_policy_add(&dm_policy);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure close success\n", __func__);
}

long ioctl_dmeasure_update_policy(unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL, *p=NULL;
	int i = 0, ret = 0, item_count=0;

	ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}
	if (!general_policy.length)
	{
		close_dmeasure();
		return 0;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! dmeasure_update_policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}
	
	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure update policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	close_dmeasure();

	item_count = general_policy.length/sizeof(struct dmeasure_policy_item);
	p=p_buff;
	for (i=0; i<item_count; i++)
	{
		struct dmeasure_policy_item *p_item = (struct dmeasure_policy_item *)p;
		
		struct dm_switch_policy dm_policy;
		dm_policy.status = 1;
		dm_policy.interval = NTOHL(p_item->be_interval_milli);

		if (strcmp(p_item->object, "syscall_table") == 0)
			syscall_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "kernel_section") == 0)
			ksection_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "idt_table") == 0)
			idt_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "module_list") == 0)
			modules_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "filesystem") == 0)
			filesystem_policy_add(&dm_policy);
		else if (strcmp(p_item->object, "network") == 0)
			net_policy_add(&dm_policy);
		else
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure update policy name[%s] error!\n", __func__, p_item->object);

		p += sizeof(struct dmeasure_policy_item);
	}
	vfree(p_buff);

	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure update policy success\n", __func__);

	return 0;
}

long ioctl_dmeasure_reload_policy(unsigned long param)
{
	close_dmeasure();
	policy_tcs_get_dmeasure_policy();

	return 0;
}

// return 0  means empty
int policy_is_empty()
{
	int ret = -1;

	if(list_empty(&p_process->policy.head)){
		ret = 0;
	}

	return ret;
}


//存在返回0，不存在返回-1
struct process_policy *query_policy_dmeasure_process(char *full_path, char* process_name, char *hash, int hash_len)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct process_policy *p_process_policy=NULL;
	int is_exist = 0;

	read_lock(&g_policy_dmeasure_process_lock);
	list_for_each_safe(pos, tmp, &p_process->policy.head)
	{
		p_process_policy = list_entry(pos, struct process_policy, list);

		switch (p_process_policy->object_id_type) 
		{
		case PROCESS_DMEASURE_OBJECT_ID_FULL_PATH:
			if (strcmp(full_path, p_process_policy->object_id) == 0)
				is_exist = 1;
			break;
		case PROCESS_DMEASURE_OBJECT_ID_PROCESS:
			if (strcmp(process_name, p_process_policy->object_id) == 0)
				is_exist = 1;
			break;
		case PROCESS_DMEASURE_OBJECT_ID_HASH:
			if ((p_process_policy->be_object_id_length==hash_len) && (memcmp(hash, p_process_policy->object_id, p_process_policy->be_object_id_length)==0))
				is_exist = 1;
			break;
		}
		
		if (is_exist)
			break;
	}
	read_unlock(&g_policy_dmeasure_process_lock);

	if (is_exist)
		return p_process_policy;

	return NULL;
}

//int update_dmeasure_process_interval_status(int interval, int status)
//{
//	int original_interval, original_status;
//
//	original_interval = p_process->original_interval;
//	original_status = p_process->original_status;
//
//	if (interval == 0)
//	{
//		//TODO 0为默认（按全局策略控制）
//		//interval = ?
//	}
//	
//	p_process->original_interval = interval;
//	p_process->original_status = status;
//	
//	if (original_interval != interval || original_status != status) {
//		modify_dmeasure_action(interval, status, DM_ACTION_TASKLIST_NAME);
//	}
//
//	return 0;
//}

void add_process_policy(struct process_policy *p_policy_dmeasure_process_item)
{
	struct list_head *pos = NULL, *tmp = NULL;
	struct process_policy *p_process_policy=NULL, *p_process_hash_policy=NULL, *p_process_name_policy=NULL;

	//hash优先级最高直接插到头部，进程名优先级最低插入尾部
	if(p_policy_dmeasure_process_item->object_id_type == PROCESS_DMEASURE_OBJECT_ID_HASH)
	{	
		list_add(&p_policy_dmeasure_process_item->list ,&p_process->policy.head);
		return;
	}
	else if(p_policy_dmeasure_process_item->object_id_type == PROCESS_DMEASURE_OBJECT_ID_PROCESS)
	{	
		list_add_tail(&p_policy_dmeasure_process_item->list ,&p_process->policy.head);
		return;
	}

	list_for_each_safe(pos, tmp, &p_process->policy.head)
	{
		p_process_policy = list_entry(pos, struct process_policy, list);

		//记录最后一个hash策略位置
		if (p_process_policy->object_id_type == PROCESS_DMEASURE_OBJECT_ID_HASH)
			p_process_hash_policy = p_process_policy;

		if (p_process_policy->object_id_type == PROCESS_DMEASURE_OBJECT_ID_FULL_PATH)
		{	
			list_add(&p_policy_dmeasure_process_item->list, &p_process_policy->list);
			return;
		}

		//记录第一个进程名策略位置
		if (p_process_policy->object_id_type == PROCESS_DMEASURE_OBJECT_ID_PROCESS)
		{	
			p_process_name_policy=p_process_policy;
			break;
		}
	}

	//全路径策略首次插入
	if(p_process_hash_policy)
		list_add(&p_policy_dmeasure_process_item->list, &p_process_policy->list); //插入到p_process_hash_policy->list后
	else if(p_process_name_policy)
		list_add_tail(&p_policy_dmeasure_process_item->list, &p_process_policy->list); //插入到p_process_name_policy->list前
	else
		list_add_tail(&p_policy_dmeasure_process_item->list, &p_process->policy.head); //策略链表为空，并且是第一个全路径策略

}

extern int collect_existed_task_info(void);
int parse_add_policy_dmeasure_process(char *p, int length, int is_start)
{
	struct dmeasure_process_item *p_item;
	struct process_policy *p_policy_dmeasure_process_item = NULL;

	p_item = (struct dmeasure_process_item *)p;
	while(length>0)
	{
		int item_len = 0;

		//转换字节序
		p_item->be_measure_interval = NTOHL(p_item->be_measure_interval);
		p_item->be_object_id_length = NTOHS(p_item->be_object_id_length);

		p_policy_dmeasure_process_item = kzalloc((sizeof(struct process_policy)+p_item->be_object_id_length+1), GFP_KERNEL); //加1，为了防止客体标识字符串长度没有包含"\0"
		if (!p_policy_dmeasure_process_item)
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc policy_dmeasure_process error!\n", __func__);
			return -1;
		}

		INIT_LIST_HEAD(&p_policy_dmeasure_process_item->list);
		atomic_set(&p_policy_dmeasure_process_item->obj_count, 0);
		p_policy_dmeasure_process_item->process_switch = 1; //打开开关
		p_policy_dmeasure_process_item->object_id_type = p_item->object_id_type;
		p_policy_dmeasure_process_item->sub_process_mode = p_item->sub_process_mode==0 ? dmeasure_feature.is_child_measure:p_item->sub_process_mode;
		p_policy_dmeasure_process_item->old_process_mode = p_item->old_process_mode==0 ? dmeasure_feature.is_exsited_process_measure:p_item->old_process_mode;
		p_policy_dmeasure_process_item->share_lib_mode = p_item->share_lib_mode==0 ? dmeasure_feature.is_lib_measure:p_item->share_lib_mode;
		p_policy_dmeasure_process_item->be_measure_interval = p_item->be_measure_interval==0 ? dmeasure_feature.time_interval:p_item->be_measure_interval;
		//p_policy_dmeasure_process_item->interval_count = p_policy_dmeasure_process_item->be_measure_interval;
		p_policy_dmeasure_process_item->be_object_id_length = p_item->be_object_id_length;
		memcpy(p_policy_dmeasure_process_item->object_id, p_item->object_id, p_item->be_object_id_length);

		//增加策略
		write_lock(&g_policy_dmeasure_process_lock);
		//list_add_tail(&p_policy_dmeasure_process_item->list, &p_process->policy.head);
		add_process_policy(p_policy_dmeasure_process_item);
		//update_dmeasure_process_interval_status(p_policy_dmeasure_process_item->be_measure_interval, 1);
		write_unlock(&g_policy_dmeasure_process_lock);

		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure_process policy add process policy object_id[%s] success\n", __func__, p_policy_dmeasure_process_item->object_id);

		//策略生效前已启动的进程是否需要度量；下发进程动态度量策略后，第一次启动时，不可以调用collect_existed_task_info，task文件hash缓存未初始化（广东公安厅项目，内核版本2.6.32）
		if ((!is_start) && (p_policy_dmeasure_process_item->old_process_mode==PROCESS_DMEASURE_MODE_MEASURE))
			collect_existed_task_info();

		item_len = sizeof(struct dmeasure_process_item) + p_item->be_object_id_length;
		BYTE4_ALIGNMENT(item_len);  //处理4字节对齐的问题
		p_item = (struct dmeasure_process_item *)((char*)p_item + item_len);
		length -= item_len;
	}

	if (length!=0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], length[%d] error!\n", __func__, length);
	}

	return 0;
}

//void remove_task_info_of_object_id(unsigned char *object_id, int object_id_length);
int parse_del_policy_dmeasure_process(char *p, int length)
{
	struct dmeasure_process_item *p_item;

	p_item = (struct dmeasure_process_item *)p;
	while(length>0)
	{
		struct list_head *pos = NULL, *tmp = NULL;
		struct process_policy *p_process_policy;
		char object_ids[512] = {0};
		int item_len = 0;
		//int is_need_del = 0;

		//转换字节序
		p_item->be_object_id_length = NTOHS(p_item->be_object_id_length);
		memcpy(object_ids, p_item->object_id, p_item->be_object_id_length);

		//删除策略
		write_lock(&g_policy_dmeasure_process_lock);
		list_for_each_safe(pos, tmp, &p_process->policy.head)
		{
			p_process_policy = list_entry(pos, struct process_policy, list);

			if ((p_process_policy->be_object_id_length==p_item->be_object_id_length) && 
				(memcmp(p_process_policy->object_id, p_item->object_id, p_item->be_object_id_length)==0))
			{
				list_del(pos);

				// 删除时，如果有正在被使用的策略，则在进程度量过程中释放内存
				if (atomic_read(&p_process_policy->obj_count))
				{
					p_process_policy->process_switch = 0;
					DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure_process policy object_id[%s] is using, set process_switch=0\n", __func__, object_ids);
				}
				else
				{
					kfree(p_process_policy);
					DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure_process policy del process policy object_id[%s] success\n", __func__, object_ids);
				}
				
				//DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], dmeasure_process policy del process policy object_id[%s] success\n", __func__, object_ids);
				break;
			}
		}
		write_unlock(&g_policy_dmeasure_process_lock);

		////删除内存采集进程的信息
		//if(is_need_del)
		//	remove_task_info_of_object_id(p_item->object_id, p_item->be_object_id_length);

		item_len = sizeof(struct dmeasure_process_item) + p_item->be_object_id_length;
		BYTE4_ALIGNMENT(item_len);  //处理4字节对齐的问题
		p_item = (struct dmeasure_process_item *)((char*)p_item + item_len);
		length -= item_len;
	}

	if (length!=0)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], length[%d] error!\n", __func__, length);
	}

	return 0;
}

int dmeasure_process_add_del_policy(int operate, unsigned long param)
{
	struct tsb_general_policy general_policy;
	char *p_buff = NULL;

	int ret =copy_from_user(&general_policy, (void *)param, sizeof(general_policy));
	if (ret || !general_policy.length) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user dmeasure_process policy error! ret[%d] policy length[%d]\n", __func__, ret, general_policy.length);
		return -1;
	}

	p_buff = vmalloc(general_policy.length);
	if (!p_buff)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], vmalloc error! dmeasure_process policy length[%d]\n", __func__, general_policy.length);
		return -1;
	}

	ret =copy_from_user(p_buff, general_policy.data, general_policy.length);
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s],  copy_from_user dmeasure_process policy failed!\n", __func__);
		vfree(p_buff);
		return -1;
	}

	if (operate==1)
		parse_add_policy_dmeasure_process(p_buff, general_policy.length, 0);
	else
		parse_del_policy_dmeasure_process(p_buff, general_policy.length);

	return 0;
}

long ioctl_dmeasure_process_add_policy(unsigned long param)
{
	dmeasure_process_add_del_policy(1, param);
	return 0;
}

long ioctl_dmeasure_process_del_policy(unsigned long param)
{
	dmeasure_process_add_del_policy(2, param);
	return 0;
}

void clean_process_policy(void)
{
	if (p_process) {

		struct list_head *pos = NULL, *tmp = NULL;
		

		write_lock(&g_policy_dmeasure_process_lock);
		list_for_each_safe(pos, tmp, &p_process->policy.head)
		{
			 struct process_policy *p_process_policy  = list_entry(pos, struct process_policy, list);

			list_del(pos);
			p_process_policy->process_switch = 0;
			//kfree(p_process_policy);
		}
		p_process->original_interval = p_process->policy.interval = 0;
		p_process->original_status = p_process->policy.status = ACTION_STATUS_DISABLED;
		write_unlock(&g_policy_dmeasure_process_lock);
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure_process policy clean success\n", __func__);
}

int policy_tcs_get_dmeasure_process_policy(int is_start)
{
	struct dmeasure_process_item *p=NULL;
	int item_count=0, length=0, ret=0;

	ret = get_dmeasure_process_policy(&p, &item_count, &length);
	if (ret)
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_dmeasure_process_policy ret[%x] error!\n", __func__, ret);
		return -1;
	}
	DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], get_dmeasure_process_policy item_count[%d] length[%d]\n", __func__, item_count, length);

	parse_add_policy_dmeasure_process((char *)p, length, is_start);

	vfree(p);

	return 0;
}

//int task_list_check(void *data);
long ioctl_dmeasure_process_reload_policy(unsigned long param)
{
	clean_process_policy();
	//task_list_check(NULL); // 调用一次动态度量接口，用以释放内存?
	policy_tcs_get_dmeasure_process_policy(0);
	return 0;
}

long ioctl_dmeasure_user_interface(unsigned long param)
{
	struct tsb_user_interface_parameter parameter;
	int ret = 0;
	char name[512] = {0};
	unsigned pid;

	ret =copy_from_user(&parameter, (void *)param, sizeof(parameter));
	if (ret) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data error! ret[%d] length[%d]\n", __func__, ret, parameter.length);
		return -1;
	}

	switch (parameter.type) {
	case TYPE_DMEASURE_KERNEL_MEMORY:
		ret =copy_from_user(name, parameter.data, parameter.length);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		ret = tsb_measure_kernel_memory(name);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] dmeasure memory name[%s], ret[%d]\n", __func__, parameter.type, name, ret);
		break;
	case TYPE_DMEASURE_KERNEL_MEMORY_ALL:
		ret = tsb_measure_kernel_memory_all();
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] dmeasure memory all, ret[%d]\n", __func__, parameter.type, ret);
		break;
	case TYPE_DMEASURE_PROCESS:
		ret =copy_from_user(&pid, parameter.data, parameter.length);
		if (ret) 
		{
			DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], copy_from_user user interface data failed!\n", __func__);
			return TSB_ERROR_SYSTEM;
		}

		ret = tsb_measure_process(pid);
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], parameter.type[%d] dmeasure process pid[%d], ret[%d]\n", __func__, parameter.type, pid, ret);
		break;
	default:
		ret = TSB_MEASURE_FAILE;
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], parameter.type[%d] error!\n", __func__, parameter.type);
		break;
	}

	return ret;
}

static void update_dmeasure_conf(struct global_control_policy* p_global_policy, uint32_t tpcm_feature, int valid_license)
{
	int is_enabled = 0;
	int dm_feature = 0;

	is_enabled = valid_license ? p_global_policy->be_dynamic_measure_on : 0;
	dm_feature =  (tpcm_feature & 0x0002) ? 1 : 0;
	if ((dmeasure_feature.is_enabled != is_enabled)
		|| (dmeasure_feature.measure_mode != dm_feature)
		|| (dmeasure_feature.time_interval != p_global_policy->be_process_dmeasure_interval)
		|| (dmeasure_feature.is_lib_measure != p_global_policy->be_process_dmeasure_lib_mode)
		|| (dmeasure_feature.is_child_measure != p_global_policy->be_process_dmeasure_sub_process_mode)
		|| (dmeasure_feature.is_exsited_process_measure != p_global_policy->be_process_dmeasure_old_process_mode))
	{
		dmeasure_feature.is_enabled = is_enabled;
		dmeasure_feature.measure_mode =  dm_feature;
		dmeasure_feature.time_interval = p_global_policy->be_process_dmeasure_interval;
		dmeasure_feature.is_lib_measure = p_global_policy->be_process_dmeasure_lib_mode;
		dmeasure_feature.is_child_measure = p_global_policy->be_process_dmeasure_sub_process_mode;
		dmeasure_feature.is_exsited_process_measure = p_global_policy->be_process_dmeasure_old_process_mode;
	}
}

void dmeasure_feature_conf_notify_func(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_dmeasure_conf(&global_policy, tpcm_feature, valid_license);
}

struct dmeasure_feature_conf *get_dmeasure_feature_conf(void)
{
	return &dmeasure_feature;
}

int dmeasure_policy_init(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_dmeasure_conf(&global_policy, tpcm_feature, valid_license);

	ret = register_feature_conf_notify(FEATURE_DMEASURE, dmeasure_feature_conf_notify_func);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_feature_conf_notify error ret[%d]!\n",__func__, ret);

	ret = ksection_policy_init();
	if (ret)
		goto ksection_out;

	ret = idt_policy_init();
	if (ret)
		goto idt_out;

	ret = syscall_policy_init();
	if (ret)
		goto syscall_out;

	ret = modules_policy_init();
	if (ret)
		goto modules_out;

	ret = filesystem_policy_init();
	if (ret)
		goto filesystem_out;

	ret = net_policy_init();
	if (ret)
		goto net_out;

	ret = process_policy_init();
	if (ret)
		goto process_out;

	policy_tcs_get_dmeasure_policy();
	policy_tcs_get_dmeasure_process_policy(1);
	register_tsb_measure_env_callback(tsb_measure_kernel_memory_all);

	if (httcsec_io_command_register(COMMAND_UPDATE_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_update_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_UPDATE_DMEASURE_POLICY);
		goto dmeasure_update_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_DMEASURE_POLICY);
		goto dmeasure_reload_out;
	}

	if (httcsec_io_command_register(COMMAND_ADD_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_add_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_ADD_DMEASURE_PROCESS_POLICY);
		goto dmeasure_process_out;
	}
	if (httcsec_io_command_register(COMMAND_DELETE_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_del_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_DELETE_DMEASURE_PROCESS_POLICY);
		goto dmeasure_process_out;
	}
	if (httcsec_io_command_register(COMMAND_RELOAD_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_reload_policy)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_RELOAD_DMEASURE_PROCESS_POLICY);
		goto dmeasure_process_out;
	}
	if (httcsec_io_command_register(COMMAND_DMEASURE_USER_INTERFACE, (httcsec_io_command_func)ioctl_dmeasure_user_interface)) {
		DEBUG_MSG(HTTC_TSB_INFO, "Command NR duplicated %d.\n", COMMAND_DMEASURE_USER_INTERFACE);
	}

	return ret;

dmeasure_process_out:
	httcsec_io_command_unregister(COMMAND_RELOAD_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_reload_policy);
dmeasure_reload_out:
	httcsec_io_command_unregister(COMMAND_UPDATE_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_update_policy);
dmeasure_update_out:
	process_policy_exit();
process_out:
	net_policy_exit();
net_out:
	filesystem_policy_exit();
filesystem_out:
	modules_policy_exit();
modules_out:
	syscall_policy_exit();
syscall_out:
	idt_policy_exit();
idt_out:
	ksection_policy_exit();
ksection_out:
	unregister_feature_conf_notify(FEATURE_DMEASURE, dmeasure_feature_conf_notify_func);
	return ret;
}

void dmeasure_policy_exit(void)
{
	httcsec_io_command_unregister(COMMAND_DMEASURE_USER_INTERFACE, (httcsec_io_command_func)ioctl_dmeasure_user_interface);
	httcsec_io_command_unregister(COMMAND_RELOAD_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_reload_policy);
	httcsec_io_command_unregister(COMMAND_DELETE_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_del_policy);
	httcsec_io_command_unregister(COMMAND_ADD_DMEASURE_PROCESS_POLICY, (httcsec_io_command_func)ioctl_dmeasure_process_add_policy);
	httcsec_io_command_unregister(COMMAND_RELOAD_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_reload_policy);
	httcsec_io_command_unregister(COMMAND_UPDATE_DMEASURE_POLICY, (httcsec_io_command_func)ioctl_dmeasure_update_policy);
	unregister_tsb_measure_env_callback(tsb_measure_kernel_memory_all);
	process_policy_exit();
	net_policy_exit();
	filesystem_policy_exit();
	modules_policy_exit();
	syscall_policy_exit();
	idt_policy_exit();
	ksection_policy_exit();
	unregister_feature_conf_notify(FEATURE_DMEASURE, dmeasure_feature_conf_notify_func);
	return;
}
