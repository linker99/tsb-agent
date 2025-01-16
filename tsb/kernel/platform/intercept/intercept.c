#include <linux/mount.h>
#include <linux/version.h>

#include "intercept.h"
#include "../utils/debug.h"
#include "intercept_impl.h"
#include "intercept_module.h"
//#include "../policy/global_policy.h"

#define intercept_module_enabled(itercept) ((itercept)->status & INTERCEPT_MODULE_STATUS_ENABLED)
int whitelist_switch = 0;

struct backup_node{
	struct list_head list;
	struct intercept_node *intercept_node;
};

static void add_to_backup(struct list_head *backup,struct intercept_node *intercept_node){
	struct backup_node *node = dkmalloc(sizeof(struct backup_node),GFP_ATOMIC);
	if(!node){
		DEBUG_MSG(HTTC_TSB_INFO,"No memory");
		return;
	}
	node->intercept_node = intercept_node;
	intercept_node->refcount++;
	list_add_tail(&node->list,backup);
}


#define CALL_INTERCEPT_MODULES(func, argsouter...) \
		int r = 0; \
		LIST_HEAD(backup); \
		struct intercept_node *node; \
		struct backup_node *backup_node,*tmp; \
		spin_lock(&intercept_lock); \
		list_for_each_entry(node,&intercept_modules,list) \
		{ \
			if (intercept_module_enabled(node->intercept) && whitelist_switch && node->intercept->func) \
			{ \
				add_to_backup(&backup,node); \
			} \
		} \
		spin_unlock(&intercept_lock); \
		list_for_each_entry_safe(backup_node,tmp,&backup,list){ \
			list_del(&backup_node->list); \
			r |= backup_node->intercept_node->intercept->func(argsouter); \
			intercept_node_post(backup_node->intercept_node); \
			dkfree(backup_node); \
		} \
		return r;

#define CALL_INTERCEPT_PTRACE_MODULES(func, argsouter...) \
		int r = 0; \
		LIST_HEAD(backup); \
		struct intercept_node *node; \
		struct backup_node *backup_node,*tmp; \
		spin_lock(&intercept_lock); \
		list_for_each_entry(node,&intercept_modules,list) \
		{ \
			if (intercept_module_enabled(node->intercept) && node->intercept->func) \
			{ \
				add_to_backup(&backup,node); \
			} \
		} \
		spin_unlock(&intercept_lock); \
		list_for_each_entry_safe(backup_node,tmp,&backup,list){ \
			list_del(&backup_node->list); \
			r |= backup_node->intercept_node->intercept->func(argsouter); \
			intercept_node_post(backup_node->intercept_node); \
			dkfree(backup_node); \
		} \
		return r;



