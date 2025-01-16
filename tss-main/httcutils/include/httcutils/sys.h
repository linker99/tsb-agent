#ifndef __HTTCUTILS_SYS_H__
#define __HTTCUTILS_SYS_H__
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"{
#endif
#include <stdint.h>

int httc_util_system (const char *cmdstring);
void httc_util_time_print (const char *format, uint64_t time);
void httc_util_rand_bytes (unsigned char *buffer, int size);

int httc_util_mv_exec(char *args, ...);
int httc_util_rm_exec(char *args, ...);
int httc_util_mkdir_exec(mode_t mode, char *args, ...);
int httc_util_chmod_exec(mode_t mode, char *args, ...);

#define httc_util_mv(args,...) httc_util_mv_exec(args, __VA_ARGS__, NULL)
#define httc_util_rm(...) httc_util_rm_exec(__VA_ARGS__, NULL)
#define httc_util_mkdir(mode, args,...) httc_util_mkdir_exec(mode, args, __VA_ARGS__, NULL)
#define httc_util_chmod(mode, args,...) httc_util_chmod_exec(mode, args, __VA_ARGS__, NULL)

#define httc_util_system_args(fmt,...)\
({\
	char _cmd[1024] = {0};\
	snprintf (_cmd, 1024, fmt, __VA_ARGS__);\
	(httc_util_system (_cmd));\
})

#ifdef __cplusplus
}
#endif

#endif	/** __HTTCUTILS_SYS_H__ */

