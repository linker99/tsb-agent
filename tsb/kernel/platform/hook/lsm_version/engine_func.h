#ifndef __HTTC_ENGINE_FUNC_H__
#define __HTTC_ENGINE_FUNC_H__

#include "../../engine/engine.h"
 
atomic_t platform_refcnt = ATOMIC_INIT(0);
extern struct httcsec_intercept_module *hookfunc;
int whitelist_switch = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 8)

#define CALL_INTERCEPT_FUNC(func, argsouter...)				\
	do {								\
		int ret = 0;						\
		struct httcsec_intercept_module *se = NULL;		\
		atomic_add(2,&platform_refcnt);				\
		se = hookfunc;						\
		if (likely(se) && likely(se->func))  		\
		{						\
			atomic_inc(&se->intercept_refcnt);	\
			atomic_dec(&platform_refcnt);		\
			ret = se->func(argsouter);		\
			atomic_dec(&se->intercept_refcnt);	\
		}						\
		else 						\
		{						\
			atomic_dec(&platform_refcnt);		\
		}						\
		atomic_dec(&platform_refcnt);				\
		return ret;						\
	} while (0)

#else  /* 4.4.0 */

#define CALL_INTERCEPT_FUNC(func, argsouter...)				\
	do {								\
		int ret = 0;						\
		struct httcsec_intercept_module *se = NULL;		\
		atomic_add(2,&platform_refcnt);				\
		se = hookfunc;						\
		ret = lsm_old_ops->func(argsouter);			\
		if (!ret)				\
		{							\
			if (likely(se) && likely(se->func))  		\
			{						\
				atomic_inc(&se->intercept_refcnt);	\
				atomic_dec(&platform_refcnt);		\
				ret = se->func(argsouter);		\
				atomic_dec(&se->intercept_refcnt);	\
			}						\
			else 						\
			{						\
				atomic_dec(&platform_refcnt);		\
			}						\
		}							\
		else							\
		{ 							\
			atomic_dec(&platform_refcnt);			\
		}							\
		atomic_dec(&platform_refcnt);				\
		return ret;						\
	} while (0)

#endif	/* < 4.4.0 */

#define CALL_SYSENGINE_FUNC(func, argsouter...)				\
	do {								\
		int ret = 0;						\
		struct httcsec_intercept_module *se = NULL;		\
		atomic_add(2,&platform_refcnt);				\
		se = hookfunc;						\
		if (likely(se) && likely(se->func))  		\
		{						\
			atomic_inc(&se->intercept_refcnt);	\
			atomic_dec(&platform_refcnt);		\
			ret = se->func(argsouter);		\
			atomic_dec(&se->intercept_refcnt);	\
		}						\
		else 						\
		{						\
			atomic_dec(&platform_refcnt);		\
		}						\
		atomic_dec(&platform_refcnt);				\
		return ret;						\
	} while (0)

#endif	/* __HTTC_ENGINE_FUNC_H__ */
