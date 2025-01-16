#ifndef __TCS_PROTECT_H__
#define __TCS_PROTECT_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif


#pragma pack(push, 1)
struct process_name{
	uint32_t be_name_length;
	char prcess_names[0];
};
struct ptrace_protect{
	uint32_t be_total_length;//数据总长度
	uint32_t be_ptrace_protect;//是否开启进程跟踪保护
	uint32_t be_ptracer_number;//例外进程（可跟踪其它进程的进程）数量，通过进程身份鉴定）
	uint32_t be_non_tracee_number;//不可被跟踪的进程数量（即使跟踪者是例外进程也不可跟踪这些进程）
	char process_names[0];//进程的名字列表
	//struct process_name[ptracer_number + untraceable_number] 4 byte align
};
#pragma pack(pop)

#endif	/** __TCS_PROTECT_H__ */

