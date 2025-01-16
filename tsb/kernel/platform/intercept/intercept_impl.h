

#ifndef SRC_DECISION_DECISION_IMPL_H_
#define SRC_DECISION_DECISION_IMPL_H_
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/list.h>
#include "../utils/debug.h"
extern struct list_head intercept_modules;
extern spinlock_t intercept_lock;
struct intercept_node{
	struct list_head list;
	struct httcsec_intercept_module *intercept;
	int refcount;
};

static inline void intercept_node_post_locked(struct intercept_node *node){

	if(--node->refcount == 0){
			dkfree(node);
	}


}
static inline void intercept_node_post(struct intercept_node *node){
	spin_lock(&intercept_lock);
	if(--node->refcount == 0){
			dkfree(node);
	}
	spin_unlock(&intercept_lock);

}

//static inline void intercept_node_post_no_resch(struct intercept_node *node){
//	while(!mutex_trylock(&intercept_lock));
//	if(--node->refcount == 0){
//			dkfree(node);
//	}
//	spin_unlock(&intercept_lock);
//
//}


#define for_each_intercept(intercept) list_for_each_entry(intercept,&intercept_modules,list)

#endif /* SRC_DECISION_DECISION_IMPL_H_ */
