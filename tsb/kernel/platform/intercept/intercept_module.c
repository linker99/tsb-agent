#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/mount.h>
#include "../utils/debug.h"
#include "intercept.h"
#include "intercept_impl.h"
#include "intercept_module.h"

#define MAX_INTERCEPT_MODULE_NUMBER 128

DEFINE_SPINLOCK(intercept_lock);
LIST_HEAD(intercept_modules);




int httcsec_register_intercept_module(struct httcsec_intercept_module *intercept)
{

	struct intercept_node *node = dkmalloc(sizeof(struct intercept_node),GFP_KERNEL);
	if(!node){
		return -ENOMEM;
	}
	memset(node,0,sizeof(struct intercept_node));
	node->intercept = intercept;
	node->refcount = 1;
	spin_lock(&intercept_lock);
	list_add_tail(&node->list,&intercept_modules);
	spin_unlock(&intercept_lock);
	return 0;
}
EXPORT_SYMBOL( httcsec_register_intercept_module);

int httcsec_unregister_intercept_module(struct httcsec_intercept_module *intercept)
{
	struct intercept_node *node,*tmp;

	spin_lock(&intercept_lock);
	list_for_each_entry_safe(node,tmp,&intercept_modules,list){

		if(intercept == node->intercept){
			list_del(&node->list);
			while(node->refcount > 1){
				spin_unlock(&intercept_lock);
				pr_dev("Wait for release\n");
				schedule_timeout_interruptible(HZ/10);//wait for all call finished
				spin_lock(&intercept_lock);
			}
			intercept_node_post_locked(node);
			break;
		}
	}
	spin_unlock(&intercept_lock);
	return 0;
}
EXPORT_SYMBOL( httcsec_unregister_intercept_module);

int httcsec_disable_intercept_module(void)
{
	struct intercept_node *node;
	spin_lock(&intercept_lock);
	list_for_each_entry(node,&intercept_modules,list){

		node->intercept->status &= ~INTERCEPT_MODULE_STATUS_ENABLED;
	}
	spin_unlock(&intercept_lock);
	return 0;
}

EXPORT_SYMBOL( httcsec_disable_intercept_module);


int httsec_enalbe_intercept_module(void)
{
	struct intercept_node *node;

	spin_lock(&intercept_lock);
	list_for_each_entry(node,&intercept_modules,list){

		node->intercept->status |= INTERCEPT_MODULE_STATUS_ENABLED;
	}
	spin_unlock(&intercept_lock);
	return 0;
}

EXPORT_SYMBOL( httsec_enalbe_intercept_module);

