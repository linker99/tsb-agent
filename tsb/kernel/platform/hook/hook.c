#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/net.h>
#include "hook.h"
#include "lsm.h"
//#include "../intercept/intercept.h"
//#include "../intercept/intercept_module.h"
#include "../utils/debug.h"
void  nethook_init(void);
void  nethook_exit(void);
//extern atomic_t platform_refcnt;
asmlinkage long (*old_sys_init_module)(void __user *umod, unsigned long len,
                                 const char __user *uargs);




int hook_init()
{
	int r = 0;

	if( (r = lsm_init()))goto out;


out:
	return r;
}


void hook_exit()
{


	lsm_exit();

}
