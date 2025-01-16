#ifndef MODULES_SYSTEM_UTILS_DEBUG_H_
#define MODULES_SYSTEM_UTILS_DEBUG_H_

#include <tpcm_sys.h>

#ifdef TPCM_LEVEL_DEBUG

enum PRINT_LEVEL{
	LEVEL_ERROR   = 1,
	LEVEL_WARNING = 2,
	LEVEL_INFO    = 3,
	LEVEL_DEBUG   = 4,
};

void tpcm_util_level_dump_hex (const void *p, int bytes);
void level_dump_hex (const void *p, int bytes);


#define LEVEL_SHOW_HEX(name,s,len) \
			do{\
				tpcm_sys_level_printf(LEVEL_DEBUG,"[DATA HEX ]  %s length=%d\n",(name),(len)); \
				if ((void *)(s) != 0) {\
					level_dump_hex((s),(len));\
				}\
			}while(0)

				
#else //#ifdef TPCM_LEVEL_DEBUG


void tpcm_util_dump_hex (const void *p, int bytes);
void dump_hex(const void *p, int bytes);

#define SHOW_HEX(name,s,len) \
	do{\
		tpcm_sys_printf("[DATA HEX ]  %s length=%d\n",(name),(len)); \
		if ((void *)(s) != 0) {\
			dump_hex((s),(len));\
		}\
	}while(0)

#endif


#endif /* MODULES_SYSTEM_UTILS_DEBUG_H_ */

