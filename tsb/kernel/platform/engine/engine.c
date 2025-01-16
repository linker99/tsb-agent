#include <linux/module.h>
#include "engine.h"
#include "../utils/debug.h"

struct httcsec_intercept_module *hookfunc = NULL;
DEFINE_SPINLOCK(httcsec_hook_lock);
extern atomic_t platform_refcnt;
int httcsec_register_hook(struct httcsec_intercept_module *old_hook,
			  struct httcsec_intercept_module *new_hook)
{
	spin_lock(&httcsec_hook_lock);
	if(old_hook != hookfunc)
	{
		spin_unlock(&httcsec_hook_lock);
		if(old_hook->httc_module != NULL)
			module_put(old_hook->httc_module);
		return -1;
	}

	if( new_hook != NULL)
	{
		hookfunc = new_hook;
	}

	spin_unlock(&httcsec_hook_lock);
	return 0;
}
EXPORT_SYMBOL(httcsec_register_hook);

int httcsec_unregister_hook( struct httcsec_intercept_module *old_hook,
			     struct httcsec_intercept_module *new_hook)
{
	spin_lock(&httcsec_hook_lock);
	if(new_hook == hookfunc)
	{
		hookfunc = old_hook;
		while(atomic_read(&new_hook->intercept_refcnt) > 0 || atomic_read(&platform_refcnt) > 1)
		{
			spin_unlock(&httcsec_hook_lock);
			DEBUG_MSG(HTTC_TSB_DEBUG, "Wait for release, intercept_refcnt[%d] platform_refcnt[%d]\n", atomic_read(&new_hook->intercept_refcnt), atomic_read(&platform_refcnt));
			schedule_timeout_interruptible(HZ/10);
			spin_lock(&httcsec_hook_lock);
		}
	}	

	if(old_hook != NULL)
		module_put(old_hook->httc_module);

	spin_unlock(&httcsec_hook_lock);
	return 0;
}
EXPORT_SYMBOL(httcsec_unregister_hook);

struct httcsec_intercept_module *httcsec_get_hook(void)
{
	struct httcsec_intercept_module *hook;
	spin_lock(&httcsec_hook_lock);
	hook = hookfunc;
	if(hook != NULL)
		try_module_get(hook->httc_module);
	spin_unlock(&httcsec_hook_lock);
	return hook;
}
EXPORT_SYMBOL(httcsec_get_hook);

