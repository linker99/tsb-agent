/*
 * debug.h
 *
 */

#ifndef _TPCM_DEBUG_H_
#define _TPCM_DEBUG_H_

//#include <tpcm_sys.h>
#include "sys_debug.h"

#ifdef TPCM_LEVEL_DEBUG

#define tpcm_var(var)  		  	//tpcm_sys_level_printf(LEVEL_DEBUG,"[VAR]\t"#var" = 0x%x\n",var)
#define tpcm_debug(fmt,...)   	//tpcm_sys_level_printf(LEVEL_DEBUG,"[DEBUG](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#define tpcm_info(fmt,...)  	tpcm_sys_level_printf(LEVEL_INFO,"[INFO](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#define tpcm_warning(fmt,...)  	tpcm_sys_level_printf(LEVEL_WARNING,"[WARNING](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#define tpcm_error(fmt,...)  	tpcm_sys_level_printf(LEVEL_ERROR,"[ERROR](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#define tpcm_fatal(fmt,...)  	tpcm_sys_level_printf(LEVEL_ERROR,"[FATAL](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)

#define tpcm_dump(name,s,len) 	//LEVEL_SHOW_HEX(name,s,len)
#define tpcm_dhash(name,s,len) 	LEVEL_SHOW_HEX(name,s,len)


#else //#ifdef TPCM_LEVEL_DEBUG


#if TPCM_DEBUG > 3 || defined(FILE_DEBUG)
#define tpcm_var(var)  		  tpcm_sys_printf("[VAR]\t"#var" = 0x%x\n",var)
#define tpcm_dump(name,s,len) SHOW_HEX(name,s,len)
#define tpcm_debug(fmt,...)  tpcm_sys_printf("[DEBUG](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#else
#define tpcm_var(var)
#define tpcm_dump(name,s,len)
#define tpcm_debug(fmt,...)
#endif

#if TPCM_DEBUG > 2  || defined(FILE_DEBUG)
#define tpcm_dhash(name,s,len) SHOW_HEX(name,s,len)
#define tpcm_info(fmt,...)  tpcm_sys_printf("[INFO](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#else
#define tpcm_info(fmt,...)
#define tpcm_dhash(name,s,len)
#endif

#if TPCM_DEBUG > 1  || defined(FILE_DEBUG)
#define tpcm_warning(fmt,...)  tpcm_sys_printf("[WARNING](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#else
#define tpcm_warning(fmt,...)
#endif

#if TPCM_DEBUG > 0  || defined(FILE_DEBUG)
#define tpcm_error(fmt,...)  tpcm_sys_printf("[ERROR](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)
#else
#define tpcm_error(fmt,...)
#endif

#define tpcm_fatal(fmt,...)  tpcm_sys_printf("[FATAL](%s:%d):\t" fmt, __func__, __LINE__,##__VA_ARGS__)

#endif //#ifdef TPCM_LEVEL_DEBUG

#endif /* MODULES_SYSTEM_UTILS_TPCM_DEBUG_H_ */
