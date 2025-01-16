#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>
#include "dmeasure_types.h"
#include "version.h"
#include "../policy/policy_dmeasure.h"
//#include "policy/list_dmeasure_trigger.h"
#include "sec_domain.h"
//#include "audit/audit_log.h"
//#include "audit/audit_filter.h"
#include "function_types.h"
#include "log/log.h"
#include "../encryption/sm3/sm3.h"
#include "tsbapi/tsb_log_notice.h"
#include "utils/debug.h"

/*init net value*/
static unsigned long netfamilies = INVALID_DATA_FULL_FF;
static unsigned long protolist = INVALID_DATA_FULL_FF;
static unsigned long protolistmutex = INVALID_DATA_FULL_FF;
module_param(netfamilies, ulong, 0644);
module_param(protolist, ulong, 0644);
module_param(protolistmutex, ulong, 0644);
MODULE_PARM_DESC(netfamilies, "ulong netfamilies address");
MODULE_PARM_DESC(protolist, "ulong protolist address");
MODULE_PARM_DESC(protolistmutex, "ulong protolistmutex address");
/*end*/

struct net_policy *net_p = NULL;

//#define ACTION_NAME "NetWork"
//#define CIRCLE_NAME   "Periodicity"
#define ACTION_NAME DM_ACTION_NETWORK_NAME

static struct net_proto_family **net_families_httc;
static struct list_head *proto_list_httc;
static struct mutex *proto_list_mutex_httc;

static DEFINE_MUTEX(dnetmeasure_lock);
static LIST_HEAD(net_proto_family_list);
static LIST_HEAD(net_proto_list);
static int net_proto_family_count;
static int net_proto_count;

struct net_proto_family_info {
	struct list_head list;
	struct net_proto_family *pf;
	int family;
	int status;
	void *create_func;
};

struct proto_info {
	struct list_head list;
	struct proto *proto;
	int status;
	int opsmem_len;
	unsigned char hash[LEN_HASH];
	//char opsmem[0];		//function close <----> get_port
};

#define FAMILY_NAME_LEN		32

static void get_family_name(int numb, char *name)
{
	switch (numb) {
	case AF_UNSPEC:
		strcpy(name, "AF_UNSPEC");
		break;
	case AF_LOCAL:		/* Unix domain sockets *//* POSIX name for AF_UNIX */
		strcpy(name, "AF_LOCAL");
		break;
	case AF_INET:		/* Internet IP Protocol */
		strcpy(name, "AF_INET");
		break;
	case AF_AX25:		/* Amateur Radio AX.25 */
		strcpy(name, "AF_AX25");
		break;
	case AF_IPX:		/* Novell IPX */
		strcpy(name, "AF_IPX");
		break;
	case AF_APPLETALK:	/* AppleTalk DDP */
		strcpy(name, "AF_APPLETALK");
		break;
	case AF_NETROM:	/* Amateur Radio NET/ROM */
		strcpy(name, "AF_NETROM");
		break;
	case AF_BRIDGE:	/* Multiprotocol bridge */
		strcpy(name, "AF_BRIDGE");
		break;
	case AF_ATMPVC:	/* ATM PVCs */
		strcpy(name, "AF_ATMPVC");
		break;
	case AF_X25:		/* Reserved for X.25 project */
		strcpy(name, "AF_X25");
		break;
	case AF_INET6:		/* IP version 6 */
		strcpy(name, "AF_INET6");
		break;
	case AF_ROSE:		/* Amateur Radio X.25 PLP */
		strcpy(name, "AF_ROSE");
		break;
	case AF_DECnet:	/* Reserved for DECnet project */
		strcpy(name, "AF_DECnet");
		break;
	case AF_NETBEUI:	/* Reserved for 802.2LLC project */
		strcpy(name, "AF_NETBEUI");
		break;
	case AF_SECURITY:	/* Security callback pseudo AF */
		strcpy(name, "AF_SECURITY");
		break;
	case AF_KEY:		/* PF_KEY key management API */
		strcpy(name, "AF_KEY");
		break;
	case AF_NETLINK:	/*  */
		strcpy(name, "AF_NETLINK");
		break;
	case AF_PACKET:	/* Packet family */
		strcpy(name, "AF_PACKET");
		break;
	case AF_ASH:		/* Ash */
		strcpy(name, "AF_ASH");
		break;
	case AF_ECONET:	/* Acorn Econet */
		strcpy(name, "AF_ECONET");
		break;
	case AF_ATMSVC:	/* ATM SVCs */
		strcpy(name, "AF_ATMSVC");
		break;
	case AF_RDS:		/* RDS sockets */
		strcpy(name, "AF_RDS");
		break;
	case AF_SNA:		/* Linux SNA Project (nutters!) */
		strcpy(name, "AF_SNA");
		break;
	case AF_IRDA:		/* IRDA sockets */
		strcpy(name, "AF_IRDA");
		break;
	case AF_PPPOX:		/* PPPoX sockets */
		strcpy(name, "AF_PPPOX");
		break;
	case AF_WANPIPE:	/* Wanpipe API Sockets */
		strcpy(name, "AF_WANPIPE");
		break;
	case AF_LLC:		/* Linux LLC */
		strcpy(name, "AF_LLC");
		break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	case AF_IB:		/* Native InfiniBand address */
		strcpy(name, "AF_IB");
		break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	case AF_MPLS:		/* MPLS */
		strcpy(name, "AF_MPLS");
		break;
#endif
	case AF_CAN:		/* Controller Area Network */
		strcpy(name, "AF_CAN");
		break;
	case AF_TIPC:		/* TIPC sockets */
		strcpy(name, "AF_TIPC");
		break;
	case AF_BLUETOOTH:	/* Bluetooth sockets */
		strcpy(name, "AF_BLUETOOTH");
		break;
	case AF_IUCV:		/* IUCV sockets */
		strcpy(name, "AF_IUCV");
		break;
	case AF_RXRPC:		/* RxRPC sockets */
		strcpy(name, "AF_RXRPC");
		break;
	case AF_ISDN:		/* mISDN sockets */
		strcpy(name, "AF_ISDN");
		break;
	case AF_PHONET:	/* Phonet sockets */
		strcpy(name, "AF_PHONET");
		break;
	case AF_IEEE802154:	/* IEEE802154 sockets */
		strcpy(name, "AF_IEEE802154");
		break;
//      case AF_CAIF:   /* CAIF sockets */
//              strcpy(name, "AF_CAIF");
//              break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 33)
    case AF_ALG:    /* Algorithm sockets */
            strcpy(name, "AF_ALG");
            break;
#endif
//      case AF_NFC:    /* NFC sockets */
//              strcpy(name, "AF_NFC");
//              break;
//    case AF_VSOCK:  /* vSockets */
//            strcpy(name, "AF_VSOCK");
//            break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	case AF_XDP:  /* XDP sockets */
		strcpy(name, "AF_XDP");
		break;
#endif
	case AF_MAX:		/* For now.. */
		strcpy(name, "AF_MAX");
		break;
	default:
		DEBUG_MSG(HTTC_TSB_DEBUG, "proto family numb is [%d]\n", numb);
		break;
	}
}

static int kernel_args_addr_init(void)
{
	if (netfamilies == INVALID_DATA_FULL_FF || netfamilies == 0 ||
	    protolist == INVALID_DATA_FULL_FF || protolist == 0/* ||
	    protolistmutex == INVALID_DATA_FULL_FF || protolistmutex == 0*/) {
		DEBUG_MSG(HTTC_TSB_INFO, "Insmod [NET] Argument Error!\n");
		return -EINVAL;
	} else {
		DEBUG_MSG(HTTC_TSB_DEBUG, "netfamilies:[%0lx]!\n", netfamilies);
		DEBUG_MSG(HTTC_TSB_DEBUG, "protolist:[%0lx]!\n", protolist);
		DEBUG_MSG(HTTC_TSB_DEBUG, "protolistmutex:[%0lx]!\n", protolistmutex);
	}

	net_families_httc = (struct net_proto_family **)netfamilies;
	proto_list_httc = (struct list_head *)protolist;
	proto_list_mutex_httc = (struct mutex *)protolistmutex;

	return 0;
}

static int add_net_proto_family_info(struct net_proto_family *pf)
{
	int ret = 0;
	char name[FAMILY_NAME_LEN];
	struct net_proto_family_info *pfi;

	pfi = kzalloc(sizeof(struct net_proto_family_info), GFP_ATOMIC);
	if (!pfi)
		return -ENOMEM;

	pfi->pf = pf;
	pfi->family = pf->family;
	pfi->create_func = pf->create;
	list_add(&pfi->list, &net_proto_family_list);
	net_proto_family_count++;

	get_family_name(pf->family, name);
	DEBUG_MSG(HTTC_TSB_DEBUG, "Add Net Family info number:[%d], name:[%s]\n", pf->family,
		name);
	return ret;
}

static int add_all_net_proto_family_info(void)
{
	int ret = 0;
	int i = 0;
	struct net_proto_family *pf = NULL;

	mutex_lock(&dnetmeasure_lock);
	for (i = 0; i < NPROTO; i++) {
		pf = net_families_httc[i];
		if (pf)
			add_net_proto_family_info(pf);
	}
	mutex_unlock(&dnetmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "net_proto_family_count:[%d]\n", net_proto_family_count);
	return ret;
}

static int remove_all_net_proto_family_info(void)
{
	struct net_proto_family_info *pfi, *tmp;

	mutex_lock(&dnetmeasure_lock);
	list_for_each_entry_safe(pfi, tmp, &net_proto_family_list, list) {
		list_del(&pfi->list);
		kfree(pfi);
		net_proto_family_count--;
	}
	mutex_unlock(&dnetmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "net_proto_family_count:[%d]\n", net_proto_family_count);
	return 0;
}

static int add_proto_info(struct proto *proto)
{
	int ret = 0;
	int len = 0;
	struct proto_info *pti;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	len = (unsigned long)&proto->get_port - (unsigned long)&proto->close + sizeof(unsigned long);
	pti = kzalloc(sizeof(struct proto_info), GFP_ATOMIC);
	if (!pti)
		return -ENOMEM;

	pti->proto = proto;
	pti->opsmem_len = len;
	//memcpy(pti->opsmem, proto, len);
	sm3_init(&ctx);
	sm3_update(&ctx, (unsigned char *)pti->proto, pti->opsmem_len);
	sm3_finish(&ctx, hash);
	memcpy(pti->hash, hash, LEN_HASH);

	list_add(&pti->list, &net_proto_list);
	net_proto_count++;
	DEBUG_MSG(HTTC_TSB_DEBUG, "Add Proto info name:%s\n", proto->name);
	return ret;
}

static int add_all_proto_info(void)
{
	int ret = 0;
	struct proto *pt = NULL;

	mutex_lock(&dnetmeasure_lock);
	//mutex_lock(proto_list_mutex_httc);
	list_for_each_entry(pt, proto_list_httc, node) {
		add_proto_info(pt);
	}
	//mutex_unlock(proto_list_mutex_httc);
	mutex_unlock(&dnetmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "proto_count:[%d]\n", net_proto_count);
	return ret;
}

int remove_all_proto_info(void)
{
	struct proto_info *pti, *tmp;

	mutex_lock(&dnetmeasure_lock);
	list_for_each_entry_safe(pti, tmp, &net_proto_list, list) {
		list_del_init(&pti->list);
		kfree(pti);
		net_proto_count--;
	}
	mutex_unlock(&dnetmeasure_lock);
	DEBUG_MSG(HTTC_TSB_DEBUG, "proto_count:[%d]\n", net_proto_count);
	return 0;
}

static int dnet_basedata_init(void)
{
	int ret = 0;

	ret = add_all_net_proto_family_info();
	if (ret)
		goto out;

	ret = add_all_proto_info();
	if (ret)
		goto out_proto;

	return ret;

out_proto:
	remove_all_net_proto_family_info();
out:
	return ret;
}

void dnet_basedata_exit(void)
{
	remove_all_net_proto_family_info();
	remove_all_proto_info();
	return;
}


//static int send_audit_log(const char *path, const char *name, int result)
static int send_audit_log(struct dmeasure_point *point, const char *name,
			  int result, unsigned char* hash)
{
	int ret = 0;
	struct sec_domain *sec_d;
	unsigned int user = 0;

	sec_d = kzalloc(sizeof(struct sec_domain), GFP_KERNEL);
	if (!sec_d) {
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], kzalloc error!\n", __func__);
		ret = -ENOMEM;
		goto out;
	}
	//if (path) {
	if (point) {
		//memcpy(sec_d->sub_name, path, strlen(path));
		memcpy(sec_d->sub_name, point->name, strlen(point->name));
	} else {
		memcpy(sec_d->sub_name, "TSB", strlen("TSB"));
	}
	memcpy(sec_d->obj_name, "network(", strlen("network("));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), name, strlen(name));
	memcpy(sec_d->obj_name+strlen(sec_d->obj_name), ")", 1);
	//memset(sec_d->sub_hash, 0, LEN_HASH);
	memcpy(sec_d->sub_hash, hash, LEN_HASH);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	user = __kuid_val(current->cred->uid);
#else
	user = current->cred->uid;
#endif

	if (point) {
		keraudit_log(TYPE_DMEASURE, point->type, result, sec_d, user,
			     current->pid);
	} else {
		keraudit_log(TYPE_DMEASURE, DMEASURE_OPERATE_PERIODICITY, result, sec_d,
			     user, current->pid);
	}

	kfree(sec_d);

out:
	return ret;
}

//static int net_proto_family_list_check(char *path)
static int net_proto_family_list_check(struct dmeasure_point *point)
{
	int ret = 0;
	char name[FAMILY_NAME_LEN] = {0};
	struct net_proto_family_info *pfi = NULL;
	struct net_proto_family *pf = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	mutex_lock(&dnetmeasure_lock);
	list_for_each_entry(pfi, &net_proto_family_list, list) {
		pf = pfi->pf;
		get_family_name(pf->family, name);
		if (/*check_family_policy(name)*/1) {
			if (pfi->family == pf->family
			    && pfi->create_func == pf->create) {
				//printk("dmeasure proto_family:[%d][%s] ok!\n",
				//       pf->family, name);
				////send_audit_log(path, name, RESULT_SUCCESS);
				//send_audit_log(point, name, RESULT_SUCCESS);
			} else {
				sm3_init(&ctx);
				sm3_update(&ctx, (unsigned char *)pf->create, sizeof(pf->create));
				sm3_finish(&ctx, hash);

				DEBUG_MSG(HTTC_TSB_DEBUG, "dmeasure proto_family:[%d][%s] err!\n", pf->family, name);
				//send_audit_log(path, name, RESULT_FAIL);
				CriticalDataFailureCount_add();
				send_audit_log(point, name, RESULT_FAIL, hash);
				ret = -EINVAL;
			}
		}
	}
	mutex_unlock(&dnetmeasure_lock);

	if (ret == 0)
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure proto_family success!\n", __func__);
		memset(hash, 0, LEN_HASH);
		send_audit_log(point, "net_proto_family", RESULT_SUCCESS, hash);
	}

	return ret;
}

//static int proto_list_check(char *path)
static int proto_list_check(struct dmeasure_point *point)
{
	int ret = 0;
	struct proto_info *protoi = NULL;
	struct proto *proto = NULL;
	sm3_context ctx;
	unsigned char hash[LEN_HASH] = {0};

	mutex_lock(&dnetmeasure_lock);
	list_for_each_entry(protoi, &net_proto_list, list) {
		proto = protoi->proto;
		if (/*check_proto_policy(proto->name)*/1) {

			sm3_init(&ctx);
			sm3_update(&ctx, (unsigned char *)protoi->proto, protoi->opsmem_len);
			sm3_finish(&ctx, hash);

			if (!memcmp(protoi->hash, hash, LEN_HASH)) {
				//printk("dmeasure netproto:[%s] ok!\n",
				//       protoi->proto->name);
				////send_audit_log(path, proto->name, RESULT_SUCCESS);
				//send_audit_log(point, proto->name,
				//	       RESULT_SUCCESS);
			} else {
				DEBUG_MSG(HTTC_TSB_INFO, "dmeasure netproto:[%s] err!\n", protoi->proto->name);
				//send_audit_log(path, proto->name, RESULT_FAIL);
				CriticalDataFailureCount_add();
				send_audit_log(point, proto->name, RESULT_FAIL, hash);
				ret = -EINVAL;
			}
		}
	}
	mutex_unlock(&dnetmeasure_lock);

	if (ret == 0)
	{
		DEBUG_MSG(HTTC_TSB_DEBUG, "Enter:[%s], dmeasure netproto success!\n", __func__);
		memset(hash, 0, LEN_HASH);
		send_audit_log(point, "proto", RESULT_SUCCESS, hash);
	}

	return ret;
}

static int net_dmeasure_check(void *data)
{
	int ret1, ret2;
	//char *path = NULL;
	struct dmeasure_point *point = NULL;

	if (data) {
		//path = (char *)data;
		point = (struct dmeasure_point *)data;
	}
	//ret1 = net_proto_family_list_check(path);
	ret1 = net_proto_family_list_check(point);
	if (ret1) {
		DEBUG_MSG(HTTC_TSB_INFO, "proto family check error!\n");
	}
	//ret2 = proto_list_check(path);
	ret2 = proto_list_check(point);
	if (ret2) {
		DEBUG_MSG(HTTC_TSB_INFO, "proto check error!\n");
	}

	return ret1 ? ret1 : ret2;
}

static struct dmeasure_node dnet_action = {
	.name = ACTION_NAME,
	.check = net_dmeasure_check,
};

int net_init(void)
{
	int ret = 0;

	ret = kernel_args_addr_init();
	if (ret)
		goto out;
	ret = dnet_basedata_init();
	if (ret) {
		ret = -EINVAL;
		goto out_net;
	}
//        get_net_policy(net_p);
	ret = dmeasure_register_action(DMEASURE_NET_ACTION, &dnet_action);
	if (ret) {
		ret = -EINVAL;
		goto out_action;
	}

	return ret;

out_action:
	dnet_basedata_exit();
out_net:
//        kfree(net_p);
out:
	return ret;
}

void net_exit(void)
{
	if (net_p)
		kfree(net_p);
	dmeasure_unregister_action(DMEASURE_NET_ACTION, &dnet_action);
	dnet_basedata_exit();
	DEBUG_MSG(HTTC_TSB_DEBUG, "######################### dmeasure net exit!\n");
	return;
}
